use delevm::opcodes::Opcode;
use delevm::syscall::Syscall;
use delevm::vm::Register;

use nom::branch::alt;
use nom::bytes::complete::{escaped, tag, take_while};
use nom::character::complete::{alphanumeric1, char, digit1, one_of};
use nom::combinator::opt;
use nom::multi::{many1, separated_list1};
use nom::sequence::{delimited, preceded};
use nom::{IResult, Parser};
use nom_locate::LocatedSpan;

#[derive(Debug, Clone, PartialEq)]
pub struct Location {
    pub file: usize,
    pub line: usize,
    pub column: usize,
}

impl Location {
    pub fn stringify(&self, file_map: &[String]) -> String {
        let file_name = if self.file < file_map.len() {
            &file_map[self.file]
        } else {
            "%anonymous%"
        };
        format!("{} @{}:{}", file_name, self.line, self.column)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum SectionKind {
    Code,
    Data,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LiteralKind {
    Hex,
    Binary,
    Decimal,
    String,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CompareKind {
    True,
    False,
    Maybe,
}

#[derive(Debug, Clone, PartialEq)]
pub enum LabelAttribute {
    Export,
}

macro_rules! define_error_tokens {
    ($($name:ident($($fields:ty),*)),* $(,)?) => {
        #[derive(Debug, Clone, PartialEq)]
        pub enum ErrorToken {
            $($name($($fields),*)),*
        }

        impl ErrorToken {
            pub fn to_str(&self) -> &'static str {
                match self {
                    $(ErrorToken::$name(..) => stringify!($name),)*
                }
            }

            pub fn err_str(&self) -> &str {
                match self {
                    $(ErrorToken::$name(msg) => msg.as_str(),)*
                }
            }
        }
    };
}

define_error_tokens! {
    InternalParserError(String),
    InvalidHexLiteral(String),
    InvalidBinaryLiteral(String),
    InvalidDecimalLiteral(String),
    StrayCharacters(String),
    IncludeNotFound(String),
    RecursiveInclude(String),
}

macro_rules! define_tokens {
    ($($name:ident($($fields:ty),*) = $id:expr),* $(,)?) => {
        #[derive(Debug, Clone, PartialEq)]
        pub enum Token {
            $($name($($fields),*)),*
        }

        impl Token {
            pub fn to_str(&self) -> &'static str {
                match self {
                    $(Token::$name(..) => stringify!($name),)*
                }
            }

            pub fn id(&self) -> usize {
                match self {
                    $(Token::$name(..) => $id,)*
                }
            }

            pub fn bitfield_id(&self) -> u64 {
                match self {
                    $(Token::$name(..) => 1u64 << ($id as u64),)*
                }
            }

            pub fn location(&self) -> &Location {
                match self {
                    $(Token::$name(loc, ..) => loc,)*
                }
            }
        }
    };
}

define_tokens! {
    Error(Location, ErrorToken) = 1,
    Comment(Location, String) = 2,
    Include(Location, String) = 3,
    Section(Location, SectionKind) = 4,
    Label(Location, (String, Vec<Result<LabelAttribute, String>>)) = 5,
    SectionAddr(Location, usize) = 6,
    Literal(Location, LiteralKind, String) = 7,
    DataEntry(Location, Vec<Token>) = 8,
    Compare(Location, CompareKind) = 9,
    CompareBlockBegin(Location, CompareKind) = 10,
    CompareBlockEnd(Location) = 11,
    Opcode(Location, Result<Opcode, String>) = 12,
    Syscall(Location, Result<Syscall, String>) = 13,
    Register(Location, Result<Register, usize>) = 14,
    Immediate(Location, (LiteralKind, String)) = 15,
    DataAddrRegister(Location, Result<Register, usize>) = 16,
    DataAddrLiteral(Location, (LiteralKind, String)) = 17,
    DataAddrLabel(Location, String) = 18,
    Instruction(Location, Vec<Token>) = 19,
}

type Span<'a> = LocatedSpan<&'a str>;

fn skip_whitespace(input: Span) -> IResult<Span, Span> {
    use nom::character::complete::multispace0;
    multispace0(input)
}

fn parse_string(input: Span) -> IResult<Span, Span> {
    let (input, _) = skip_whitespace(input)?;
    let (input, _) = char('"')(input)?;
    let (input, s) = escaped(
        one_of(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_!@#$%^&*()-=+[]{}|;:',.<>?/",
        ),
        '\\',
        one_of(r#""nrt\"#),
    )(input)?;
    let (input, _) = char('"')(input)?;

    Ok((input, s))
}

fn unescape(input: &str) -> String {
    let mut result = String::new();
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            if let Some(next) = chars.next() {
                match next {
                    'n' => result.push('\n'),
                    'r' => result.push('\r'),
                    't' => result.push('\t'),
                    '"' => result.push('"'),
                    '\\' => result.push('\\'),
                    _ => result.push(next),
                }
            }
        } else {
            result.push(c);
        }
    }

    result
}

fn parse_include(file: usize, line: usize, input: Span) -> IResult<Span, (Location, String)> {
    let (input, _) = skip_whitespace(input)?;
    let (input, location) = tag("$include")(input)?;
    let (input, _) = skip_whitespace(input)?;
    let (input, path) = parse_string(input)?;

    let location = Location {
        file,
        line,
        column: location.get_utf8_column(),
    };

    Ok((input, (location, unescape(path.fragment()))))
}

fn parse_comment(file: usize, line: usize, input: Span) -> IResult<Span, Token> {
    let (input, _) = skip_whitespace(input)?;
    let (comment, _) = char(';')(input)?;

    let location = Location {
        file,
        line,
        column: input.get_utf8_column(),
    };

    Ok((
        Span::new(""),
        Token::Comment(location, comment.fragment().to_string()),
    ))
}

fn parse_section(file: usize, line: usize, input: Span) -> IResult<Span, Token> {
    let (input, _) = skip_whitespace(input)?;
    let (input, location) = tag("$")(input)?;
    let (input, section) = alt((tag("code"), tag("data"))).parse(input)?;

    let location = Location {
        file,
        line,
        column: location.get_utf8_column(),
    };

    let section_kind = match *section.fragment() {
        "code" => SectionKind::Code,
        "data" => SectionKind::Data,
        _ => unreachable!(),
    };

    Ok((input, Token::Section(location, section_kind)))
}

fn parse_label_line(file: usize, line: usize, input: Span) -> IResult<Span, Token> {
    let (input, _) = skip_whitespace(input)?;
    let (input, location) = tag(".")(input)?;
    let (input, name) = many1(one_of(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_",
    ))
    .map(|v: Vec<_>| v.into_iter().collect::<String>())
    .parse(input)?;

    let (input, _) = skip_whitespace(input)?;

    let (input, attributes) = opt(delimited(
        char('('),
        separated_list1(
            delimited(skip_whitespace, char(','), skip_whitespace),
            alphanumeric1,
        ),
        char(')'),
    ))
    .parse(input)?;

    let attributes = attributes.map_or(vec![], |attrs| {
        attrs
            .iter()
            .map(|attr| match *attr.fragment() {
                "export" => Ok(LabelAttribute::Export),
                _ => Err(attr.fragment().to_string()),
            })
            .collect::<Vec<_>>()
    });

    let (input, _) = char(':')(input)?;

    let location = Location {
        file,
        line,
        column: location.get_utf8_column(),
    };

    Ok((input, Token::Label(location, (name, attributes))))
}

// parses a decimal literal, which is a sequence of base10 digits
fn parse_decimal_literal(input: Span) -> IResult<Span, (LiteralKind, Span)> {
    let (input, _) = skip_whitespace(input)?;

    let (input, num) = digit1(input)?;

    if num.fragment().chars().all(|c| c.is_digit(10)) {
        Ok((input, (LiteralKind::Decimal, num)))
    } else {
        Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Digit,
        )))
    }
}

// parses a binary literal, which starts with "0b" followed by a sequence of 0s and 1s
// a length can be specified, which is the expected length of the binary string, excluding the "0b" prefix
fn parse_binary_literal(input: Span, length: Option<usize>) -> IResult<Span, (LiteralKind, Span)> {
    let (input, _) = skip_whitespace(input)?;

    let (input, bin) =
        preceded(tag("0b"), take_while(|c: char| c == '0' || c == '1')).parse(input)?;

    if let Some(length) = length {
        if bin.len() != length {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::LengthValue,
            )));
        }
    }

    Ok((input, (LiteralKind::Binary, bin)))
}

// parses a hex literal, which starts with "0x" followed by alphanumeric characters
// a length can be specified, which is the expected length of the hex string, excluding the "0x" prefix
fn parse_hex_literal(input: Span, length: Option<usize>) -> IResult<Span, (LiteralKind, Span)> {
    let (input, _) = skip_whitespace(input)?;
    let (input, hex) = preceded(tag("0x"), take_while(|c: char| c.is_digit(16))).parse(input)?;

    if let Some(length) = length {
        if hex.fragment().chars().count() != length {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::LengthValue,
            )));
        }
    }

    if hex.fragment().chars().all(|c| c.is_digit(16)) {
        Ok((input, (LiteralKind::Hex, hex)))
    } else {
        Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Digit,
        )))
    }
}

fn parse_string_literal(input: Span, length: Option<usize>) -> IResult<Span, (LiteralKind, Span)> {
    let (input, _) = skip_whitespace(input)?;
    let (input, string) = parse_string(input)?;

    if let Some(length) = length {
        if string.fragment().len() != length {
            return Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::LengthValue,
            )));
        }
    }

    Ok((input, (LiteralKind::String, string)))
}

fn parse_section_addr(file: usize, line: usize, input: Span) -> IResult<Span, Token> {
    let (input, _) = skip_whitespace(input)?;
    let (input, (_, addr)) = parse_hex_literal(input, Some(4))?;

    let location = Location {
        file,
        line,
        column: addr.get_utf8_column(),
    };

    match usize::from_str_radix(&addr.fragment(), 16) {
        Ok(addr_value) => Ok((input, Token::SectionAddr(location, addr_value))),
        Err(_) => Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Digit,
        ))),
    }
}

fn parse_cmp_block_begin(file: usize, line: usize, input: Span) -> IResult<Span, Token> {
    let (input, _) = skip_whitespace(input)?;
    let (input, location) = tag("@")(input)?;
    let (input, cmp_kind) = alt((char('t'), char('f'), char('m'))).parse(input)?;
    let cmp_kind = match cmp_kind {
        't' => CompareKind::True,
        'f' => CompareKind::False,
        'm' => CompareKind::Maybe,
        _ => unreachable!(),
    };

    let (input, _) = skip_whitespace(input)?;
    let (input, _) = char('[')(input)?;

    let location = Location {
        file,
        line,
        column: location.get_utf8_column(),
    };

    Ok((input, Token::CompareBlockBegin(location, cmp_kind)))
}

fn parse_cmp_block_end(file: usize, line: usize, input: Span) -> IResult<Span, Token> {
    let (input, _) = skip_whitespace(input)?;
    let (input, location) = tag("]")(input)?;

    let location = Location {
        file,
        line,
        column: location.get_utf8_column(),
    };

    Ok((input, Token::CompareBlockEnd(location)))
}

fn parse_data_entry(file: usize, line: usize, input: Span) -> IResult<Span, Token> {
    let (input, _) = skip_whitespace(input)?;

    let location = input.get_utf8_column();

    let (input, tokens) = separated_list1(
        delimited(skip_whitespace, char(','), skip_whitespace),
        alt((
            |i| parse_hex_literal(i, None),
            |i| parse_binary_literal(i, None),
            |i| parse_decimal_literal(i),
            |i| parse_string_literal(i, None),
        )),
    )
    .map(|v: Vec<(LiteralKind, Span)>| {
        v.into_iter()
            .map(|(kind, span)| match kind {
                LiteralKind::Hex => Token::Literal(
                    Location {
                        file,
                        line,
                        column: span.get_utf8_column() - 2,
                    },
                    LiteralKind::Hex,
                    span.fragment().to_string(),
                ),
                LiteralKind::Binary => Token::Literal(
                    Location {
                        file,
                        line,
                        column: span.get_utf8_column() - 2,
                    },
                    LiteralKind::Binary,
                    span.fragment().to_string(),
                ),
                LiteralKind::Decimal => Token::Literal(
                    Location {
                        file,
                        line,
                        column: span.get_utf8_column(),
                    },
                    LiteralKind::Decimal,
                    span.fragment().to_string(),
                ),
                LiteralKind::String => Token::Literal(
                    Location {
                        file,
                        line,
                        column: span.get_utf8_column() - 1,
                    },
                    LiteralKind::String,
                    unescape(span.fragment()),
                ),
            })
            .collect::<Vec<Token>>()
    })
    .parse(input)?;

    if tokens.is_empty() {
        return Err(nom::Err::Error(nom::error::Error::new(
            input,
            nom::error::ErrorKind::Eof,
        )));
    }

    let location = Location {
        file,
        line,
        column: location,
    };

    Ok((
        input,
        Token::DataEntry(location, tokens.into_iter().collect::<Vec<Token>>()),
    ))
}

fn parse_data_entry_line(
    file: usize,
    line: usize,
    input: Span,
) -> IResult<Span, (Option<Token>, Token)> {
    let (mut input, _) = skip_whitespace(input)?;

    let mut section_addr = None;

    if let Ok((new_input, addr)) = parse_section_addr(file, line, input) {
        section_addr = Some(addr);
        input = new_input;
    }

    let (input, data_entry) = parse_data_entry(file, line, input)?;

    Ok((input, (section_addr, data_entry)))
}

fn parse_instruction_cmp(file: usize, line: usize, input: Span) -> IResult<Span, Token> {
    let (input, _) = skip_whitespace(input)?;
    let (input, location) = tag("@")(input)?;
    let (input, cmp_kind) = alt((char('t'), char('f'), char('m'))).parse(input)?;
    let cmp_kind = match cmp_kind {
        't' => CompareKind::True,
        'f' => CompareKind::False,
        'm' => CompareKind::Maybe,
        _ => unreachable!(),
    };

    Ok((
        input,
        Token::Compare(
            Location {
                file,
                line,
                column: location.get_utf8_column(),
            },
            cmp_kind,
        ),
    ))
}

fn parse_opcode_name(file: usize, line: usize, input: Span) -> IResult<Span, Token> {
    let (input, _) = skip_whitespace(input)?;
    let column = input.get_utf8_column();
    let (input, name) = many1(one_of(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_",
    ))
    .parse(input)?;

    let name = name.into_iter().collect::<String>();

    let location = Location { file, line, column };

    match Opcode::from_asm_name(&name) {
        Some(opcode) => Ok((input, Token::Opcode(location, Ok(opcode)))),
        None => Ok((input, Token::Opcode(location, Err(name)))),
    }
}

fn parse_syscall_arg(file: usize, line: usize, input: Span) -> IResult<Span, Token> {
    let (input, _) = skip_whitespace(input)?;
    let column = input.get_utf8_column();
    let (input, name) = many1(one_of(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_",
    ))
    .map(|v: Vec<_>| v.into_iter().collect::<String>())
    .parse(input)?;

    let location = Location { file, line, column };

    match Syscall::from_asm_name(&name) {
        Some(syscall) => Ok((input, Token::Syscall(location, Ok(syscall)))),
        None => Ok((input, Token::Syscall(location, Err(name)))),
    }
}

fn parse_register_arg(file: usize, line: usize, input: Span) -> IResult<Span, Token> {
    let (input, _) = skip_whitespace(input)?;
    let column = input.get_utf8_column();
    let (input, reg) = preceded(char('R'), digit1).parse(input)?;

    let location = Location { file, line, column };

    match Register::from_str(reg.fragment()) {
        Some(register) => Ok((input, Token::Register(location, Ok(register)))),
        None => match reg.fragment().parse::<usize>() {
            Ok(index) => Ok((input, Token::Register(location, Err(index)))),
            Err(_) => Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Digit,
            ))),
        },
    }
}

fn parse_label_arg(file: usize, line: usize, input: Span) -> IResult<Span, Token> {
    let (input, _) = skip_whitespace(input)?;
    let column = input.get_utf8_column();
    let (input, _) = tag(".")(input)?;
    let (input, name) = many1(one_of(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_",
    ))
    .map(|v: Vec<_>| v.into_iter().collect::<String>())
    .parse(input)?;

    Ok((
        input,
        Token::Label(Location { file, line, column }, (name, Vec::new())),
    ))
}

fn parse_immediate_arg(file: usize, line: usize, input: Span) -> IResult<Span, Token> {
    let (input, _) = skip_whitespace(input)?;
    let column = input.get_utf8_column();
    let (input, _) = char('#')(input)?;
    let (input, (kind, span)) = alt((
        |i| parse_hex_literal(i, None),
        |i| parse_binary_literal(i, None),
        |i| parse_decimal_literal(i),
        |i| parse_string_literal(i, None),
    ))
    .parse(input)?;

    Ok((
        input,
        Token::Immediate(
            Location { file, line, column },
            (kind, span.fragment().to_string()),
        ),
    ))
}

fn parse_data_addr_register_arg(file: usize, line: usize, input: Span) -> IResult<Span, Token> {
    let (input, _) = skip_whitespace(input)?;
    let column = input.get_utf8_column();
    let (input, _) = tag("data[")(input)?;
    let (input, reg) = preceded(char('R'), digit1).parse(input)?;

    let location = Location { file, line, column };

    match Register::from_str(reg.fragment()) {
        Some(register) => Ok((input, Token::DataAddrRegister(location, Ok(register)))),
        None => match reg.fragment().parse::<usize>() {
            Ok(index) => Ok((input, Token::DataAddrRegister(location, Err(index)))),
            Err(_) => Err(nom::Err::Error(nom::error::Error::new(
                input,
                nom::error::ErrorKind::Digit,
            ))),
        },
    }
}

fn parse_data_addr_literal_arg(file: usize, line: usize, input: Span) -> IResult<Span, Token> {
    let (input, _) = skip_whitespace(input)?;
    let column = input.get_utf8_column();
    let (input, _) = tag("data[")(input)?;
    let (input, literal) = alt((
        |i| parse_hex_literal(i, None),
        |i| parse_binary_literal(i, None),
        |i| parse_decimal_literal(i),
    ))
    .parse(input)?;
    let (input, _) = char(']')(input)?;

    let (kind, span) = literal;

    Ok((
        input,
        Token::DataAddrLiteral(
            Location { file, line, column },
            (kind, span.fragment().to_string()),
        ),
    ))
}

fn parse_data_addr_label_arg(file: usize, line: usize, input: Span) -> IResult<Span, Token> {
    let (input, _) = skip_whitespace(input)?;
    let column = input.get_utf8_column();
    let (input, _) = tag("data[")(input)?;
    let (input, _) = tag(".")(input)?;
    let (input, name) = many1(one_of(
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_",
    ))
    .map(|v: Vec<_>| v.into_iter().collect::<String>())
    .parse(input)?;
    let (input, _) = char(']')(input)?;

    Ok((
        input,
        Token::DataAddrLabel(Location { file, line, column }, name),
    ))
}

fn parse_instruction_line(file: usize, line: usize, input: Span) -> IResult<Span, Token> {
    let (mut input, _) = skip_whitespace(input)?;
    let column = input.get_utf8_column();

    let mut section_addr = None;
    if let Ok((new_input, addr)) = parse_section_addr(file, line, input) {
        section_addr = Some(addr);
        input = new_input;
    }

    let mut cmp_flag = None;
    if let Ok((new_input, cmp)) = parse_instruction_cmp(file, line, input) {
        cmp_flag = Some(cmp);
        input = new_input;
    }

    let (input, _) = skip_whitespace(input)?;

    let (input, opcode) = parse_opcode_name(file, line, input)?;

    let (input, args) = separated_list1(
        delimited(skip_whitespace, char(','), skip_whitespace),
        alt((
            |i| parse_data_addr_register_arg(file, line, i),
            |i| parse_data_addr_literal_arg(file, line, i),
            |i| parse_data_addr_label_arg(file, line, i),
            |i| parse_register_arg(file, line, i),
            |i| parse_syscall_arg(file, line, i),
            |i| parse_label_arg(file, line, i),
            |i| parse_immediate_arg(file, line, i),
        )),
    )
    .parse(input)?;

    let mut instruction_tokens = Vec::new();
    if let Some(addr) = section_addr {
        instruction_tokens.push(addr);
    }
    if let Some(cmp) = cmp_flag {
        instruction_tokens.push(cmp);
    }
    instruction_tokens.push(opcode);

    instruction_tokens.extend(args);

    Ok((
        input,
        Token::Instruction(Location { file, line, column }, instruction_tokens),
    ))
}

// tokenizes input string into tokens, given a file index and a file reader function
// the file reader fn is called if an include is encountered, and it should return
// the new file index and the content of the file as a String
//
// to prevent recursive includes, upon reading a new file, if the stack contains
// the returned file index, the function simply returns an error token
// when entering a new file, the file index is pushed onto the stack,
// and when exiting the file, it is popped from the stack
fn tokenize_impl(
    src: &String,
    file: usize,
    file_index_stack: &mut Vec<usize>,
    filenames: &mut Vec<String>,
    file_reader: &mut dyn FnMut(&str, &mut Vec<String>) -> Option<(usize, String)>,
) -> Vec<Token> {
    if src.is_empty() {
        return Vec::new();
    }

    let mut tokens = Vec::new();
    file_index_stack.push(file);

    let mut current_location = Location {
        file,
        line: 0,
        column: 0,
    };

    for line in src.lines() {
        current_location.column = 0;
        current_location.line += 1;

        if line.trim().is_empty() {
            continue; // skip empty lines
        }

        println!("{}", line);

        let span = Span::new(line);

        // sections: $code or $data, followed by optional whitespace, optional comment, EOL
        if let Ok((span, token)) = parse_section(file, current_location.line, span) {
            tokens.push(token);

            if let Ok((_, token)) = parse_comment(file, current_location.line, span) {
                tokens.push(token);
            }

            let (span, _) = skip_whitespace(span).unwrap();

            if span.len() != 0 {
                tokens.push(Token::Error(
                    Location {
                        file: current_location.file,
                        line: current_location.line,
                        column: current_location.column + span.location_offset(),
                    },
                    ErrorToken::StrayCharacters(span.fragment().to_string()),
                ));
            }

            continue;
        }

        // labels: .label_name:, followed by optional whitespace, optional comment, EOL
        if let Ok((span, token)) = parse_label_line(file, current_location.line, span) {
            tokens.push(token);

            if let Ok((_, token)) = parse_comment(file, current_location.line, span) {
                tokens.push(token);
            }

            let (span, _) = skip_whitespace(span).unwrap();

            if span.len() != 0 {
                tokens.push(Token::Error(
                    Location {
                        file: current_location.file,
                        line: current_location.line,
                        column: current_location.column + span.location_offset(),
                    },
                    ErrorToken::StrayCharacters(span.fragment().to_string()),
                ));
            }

            continue;
        }

        // includes: $include "path/to/file", followed by optional whitespace, optional comment, EOL
        if let Ok((span, (loc, path))) = parse_include(file, current_location.line, span) {
            if let Some((file_id, contents)) = file_reader(&path, filenames) {
                if file_index_stack.contains(&file_id) {
                    tokens.push(Token::Error(
                        loc.clone(),
                        ErrorToken::RecursiveInclude(path),
                    ));
                } else {
                    filenames.push(path.clone());
                    tokens.append(&mut tokenize_impl(
                        &contents,
                        file_id,
                        file_index_stack,
                        filenames,
                        file_reader,
                    ));
                }
            } else {
                tokens.push(Token::Error(loc.clone(), ErrorToken::IncludeNotFound(path)));
            }

            if let Ok((_, token)) = parse_comment(file, current_location.line, span) {
                tokens.push(token);
            }

            let (span, _) = skip_whitespace(span).unwrap();

            if span.len() != 0 {
                tokens.push(Token::Error(
                    loc,
                    ErrorToken::StrayCharacters(span.fragment().to_string()),
                ));
            }

            continue;
        }

        if let Ok((span, data_entry)) = parse_data_entry_line(file, current_location.line, span) {
            let (section_addr, data_entry) = data_entry;

            if let Some(addr) = section_addr {
                tokens.push(addr);
            }

            tokens.push(data_entry);

            if let Ok((_, token)) = parse_comment(file, current_location.line, span) {
                tokens.push(token);
            } else if span.trim_end().len() != 0 {
                tokens.push(Token::Error(
                    Location {
                        file: current_location.file,
                        line: current_location.line,
                        column: current_location.column + span.location_offset(),
                    },
                    ErrorToken::StrayCharacters(span.fragment().to_string()),
                ));
            }

            continue;
        }

        if let Ok((span, cmp_block_begin)) =
            parse_cmp_block_begin(file, current_location.line, span)
        {
            tokens.push(cmp_block_begin);

            if let Ok((_, token)) = parse_comment(file, current_location.line, span) {
                tokens.push(token);
            }

            let (span, _) = skip_whitespace(span).unwrap();

            if span.len() != 0 {
                tokens.push(Token::Error(
                    Location {
                        file: current_location.file,
                        line: current_location.line,
                        column: current_location.column + span.location_offset(),
                    },
                    ErrorToken::StrayCharacters(span.fragment().to_string()),
                ));
            }

            continue;
        }

        if let Ok((span, cmp_block_end)) = parse_cmp_block_end(file, current_location.line, span) {
            tokens.push(cmp_block_end);

            if let Ok((_, token)) = parse_comment(file, current_location.line, span) {
                tokens.push(token);
            }

            let (span, _) = skip_whitespace(span).unwrap();

            if span.len() != 0 {
                tokens.push(Token::Error(
                    Location {
                        file: current_location.file,
                        line: current_location.line,
                        column: current_location.column + span.location_offset(),
                    },
                    ErrorToken::StrayCharacters(span.fragment().to_string()),
                ));
            }

            continue;
        }

        if let Ok((span, instruction)) = parse_instruction_line(file, current_location.line, span) {
            tokens.push(instruction);

            let (span, _) = skip_whitespace(span).unwrap();

            if let Ok((_, token)) = parse_comment(file, current_location.line, span) {
                tokens.push(token);
            } else if span.trim_end().len() != 0 {
                tokens.push(Token::Error(
                    Location {
                        file: current_location.file,
                        line: current_location.line,
                        column: current_location.column + span.location_offset(),
                    },
                    ErrorToken::StrayCharacters(span.fragment().to_string()),
                ));
            }

            continue;
        }

        if let Ok((_, token)) = parse_comment(file, current_location.line, span) {
            tokens.push(token);
            continue;
        }

        tokens.push(Token::Error(
            Location {
                file: current_location.file,
                line: current_location.line,
                column: current_location.column + span.location_offset(),
            },
            ErrorToken::StrayCharacters(span.fragment().to_string()),
        ));
    }

    file_index_stack.pop();
    tokens
}

pub fn tokenize(filename: String, src: &String) -> (Vec<Token>, Vec<String>) {
    let mut filenames = vec![filename];
    let mut file_reader = |_name: &str, _filenames: &mut Vec<String>| {
        // placeholder for file reading logic
        // filenames.push("placeholder_file".to_string());
        None::<(usize, String)>
    };

    // start with file index 0, which is the main source file
    let mut file_index_stack = Vec::new();
    (
        tokenize_impl(
            src,
            0,
            &mut file_index_stack,
            &mut filenames,
            &mut file_reader,
        ),
        filenames,
    )
}

pub fn stringify_tokens(tokens: &Vec<Token>, file_map: &[String]) -> String {
    let mut parts = vec![];

    for tok in tokens.iter() {
        parts.push(format!("[{}]\t", tok.location().stringify(file_map)));

        match tok {
            Token::Error(_, err) => {
                parts.push(format!("Error: {} {}\n", err.to_str(), err.err_str()));
            }
            Token::Comment(_, err) => {
                parts.push(format!("Comment: ;{}\n", err));
            }
            Token::Include(_, path) => {
                parts.push(format!("Include: $include \"{}\"\n", path));
            }
            Token::Section(_, kind) => {
                let section_str = match kind {
                    SectionKind::Code => "$code",
                    SectionKind::Data => "$data",
                };
                parts.push(format!("Section: {}\n", section_str));
            }
            Token::Label(_, (name, attrs)) => {
                parts.push(format!("Label: .{} ({:?}):\n", name, attrs));
            }
            Token::SectionAddr(_, addr) => {
                parts.push(format!("Section Address: 0x{:04X}\n", addr));
            }
            Token::Literal(_, kind, value) => {
                let kind_str = match kind {
                    LiteralKind::Hex => "Hex",
                    LiteralKind::Binary => "Binary",
                    LiteralKind::Decimal => "Decimal",
                    LiteralKind::String => "String",
                };
                parts.push(format!("Literal: {} {}\n", kind_str, value));
            }
            Token::DataEntry(_, entries) => {
                let entry_str = entries
                    .iter()
                    .map(|e| {
                        format!("{}", match e {
                            Token::Literal(_, kind, value) => match kind {
                                LiteralKind::Hex => format!("0x{}", value),
                                LiteralKind::Binary => format!("0b{}", value),
                                LiteralKind::Decimal => value.clone(),
                                LiteralKind::String => format!("\"{}\"", value),
                            },
                            _ => e.to_str().to_string(),
                        })
                    })
                    .collect::<Vec<String>>()
                    .join(", ");
                parts.push(format!("Data Entry: [{}]\n", entry_str));
            }
            Token::CompareBlockBegin(_, kind) => {
                let kind_str = match kind {
                    CompareKind::True => "t",
                    CompareKind::False => "f",
                    CompareKind::Maybe => "m",
                };
                parts.push(format!("Compare Block Begin: @{} [\n", kind_str));
            }
            Token::CompareBlockEnd(_) => {
                parts.push(format!("Compare Block End: ]\n"));
            }
            Token::Instruction(_, args) => parts.push(format!(
                "Instruction: [{}]\n",
                args.iter()
                    .map(|arg| {
                        match arg {
                            Token::Compare(_, kind) => format!("{}", match kind {
                                CompareKind::True => "@t",
                                CompareKind::False => "@f",
                                CompareKind::Maybe => "@m",
                            }),
                            Token::Opcode(_, opcode) => match opcode {
                                Ok(op) => format!("{}", op.to_asm_name()),
                                Err(name) => format!("! {}", name),
                            },
                            Token::SectionAddr(_, addr) => {
                                format!("0x{:04X}", addr)
                            }
                            Token::Label(_, (name, _)) => {
                                format!(".{}", name)
                            }
                            Token::Syscall(_, syscall) => match syscall {
                                Ok(syscall) => format!("{}", syscall.to_asm_name()),
                                Err(name) => format!("! {}", name),
                            },
                            Token::Register(_, Ok(reg)) => {
                                format!("{}", reg.to_str())
                            }
                            Token::Immediate(_, imm) => {
                                format!("#{}", match imm.0 {
                                    LiteralKind::Hex => format!("0x{}", imm.1),
                                    LiteralKind::Binary => format!("0b{}", imm.1),
                                    LiteralKind::Decimal => imm.1.clone(),
                                    LiteralKind::String => format!("\"{}\"", unescape(&imm.1)),
                                })
                            }
                            Token::DataAddrRegister(_, Ok(reg)) => {
                                format!("data[R{}]", reg.to_str())
                            }
                            Token::DataAddrLiteral(_, (kind, value)) => {
                                format!("data[{}]", match kind {
                                    LiteralKind::Hex => format!("0x{}", value),
                                    LiteralKind::Binary => format!("0b{}", value),
                                    LiteralKind::Decimal => value.clone(),
                                    LiteralKind::String => format!("\"{}\"", unescape(value)),
                                })
                            }
                            Token::DataAddrLabel(_, name) => {
                                format!("data[.{}]", name)
                            }
                            _ => format!("{}", arg.to_str()),
                        }
                    })
                    .collect::<Vec<String>>()
                    .join(", ")
            )),
            _ => parts.push(format!("{}\n", tok.to_str().to_string())),
        }
    }

    parts.join("")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tokenize_1() {
        let src = r#"
; this is a comment   
$code
$include "file_with_\"cursed\"_name.dasm"   

.main(export, delectruh):
0x0000  load R0, data[.D0]
        load R10, #0x0123
.L0:
0x0001  and R3, R0, R1
        iequ R2, R3
        @t [
            push R0
            syscall R0, R1, print_i64
        ]
        @t pop R0
        iadd R1, R0, R1
        jump .L0

$data  
.D0:
0x0123 1,2   , 0b0101, 0x01, "meow"
"#;

        let (tokens, file_map) = tokenize("file".to_string(), &src.to_string());

        println!("{}", stringify_tokens(&tokens, &file_map))
    }
}
