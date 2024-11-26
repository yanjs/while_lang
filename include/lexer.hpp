#pragma once
#include <string>
#include <memory>
#include <variant>
#include <cctype>
#include <iostream>
#include <optional>

namespace wl {

struct Eof {};
struct Keyword {
  enum Kind {
    If,
    Then,
    Else,
    Fi,
    While,
    Do,
    Od,
    Func,
    Cnuf,
    Skip,
    True,
    False,
    Not,
    And,
    Or,
    Mod,
    
    Plus,
    Minus,
    Mul,
    Div,
    Seq,
    Comma,
    Asgn,
    Gt,
    Ge,
    Lt,
    Le,
    Eq,
    Neq,

    LParen,
    RParen,

    KIND_COUNT,
  };
  constexpr static const char* keywords[] = {
    "if",
    "then",
    "else",
    "fi",
    "while",
    "do",
    "od",
    "func",
    "cnuf",
    "skip",
    "true",
    "false",
    "not",
    "and",
    "or",
    "mod",

    "+",
    "-",
    "*",
    "/",
    ";",
    ",",
    ":=",
    ">",
    ">=",
    "<",
    "<=",
    "==",
    "!=",

    "(",
    ")",
  };
  static_assert(sizeof(keywords) / sizeof(keywords[0]) == KIND_COUNT,
    "Number of keywords must be equal to number of Kind");
  Kind kind;
};
struct Identifier {
  std::string name;
};
struct Number {
  double val;
};

struct Unknown {
  int ch;
};

using Token = std::variant<
  Eof,
  Keyword,
  Identifier,
  Number,
  Unknown
>;

class Lexer {
  std::istream& in{std::cin};
  int last_char{' '};
  std::unique_ptr<Token> curr_token;
  void next_token();
public:
  Lexer(std::istream& in = std::cin);
  std::unique_ptr<Token> get_token();
  Token* peek_token();
};

} // namespace wl