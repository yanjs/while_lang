#include "lexer.hpp"
#include <cstdio>
#include <cassert>

namespace wl {

Lexer::Lexer(std::istream& in) : in(in) {}

std::unique_ptr<Token> Lexer::get_token() {
  if (!curr_token) {
    next_token();
  }
  assert(curr_token);

  return std::move(curr_token);
}

Token *Lexer::peek_token() {
  if (!curr_token) {
    next_token();
  }
  assert(curr_token);
  return curr_token.get();
}

void Lexer::next_token() {
  // skip whitespaces
  while (std::isspace(last_char)) {
    last_char = in.get();
  }

  // identifier or keyword
  if (std::isalpha(last_char)) {
    std::string name;
    do {
      name += last_char;
      last_char = in.get();
    } while (std::isalnum(last_char));

    for (size_t i = 0; i < sizeof(Keyword::keywords) / sizeof(Keyword::keywords[0]); ++i) {
      if (name == Keyword::keywords[i]) {
        curr_token = std::make_unique<Token>(Keyword{static_cast<Keyword::Kind>(i)});
        return;
      }
    }

    curr_token = std::make_unique<Token>(Identifier{name});
    return;
  }

  // number
  if (std::isdigit(last_char) || last_char == '.') {
    std::string num;
    do {
      num += last_char;
      last_char = in.get();
    } while (std::isdigit(last_char) || last_char == '.');

    double val = std::stod(num);
    curr_token = std::make_unique<Token>(Number{val});
    return;
  }

  // symbol
  if (std::ispunct(last_char)) {
    std::string sym;
    do {
      sym += last_char;
      last_char = in.get();
      for (size_t i = 0; i < sizeof(Keyword::keywords) / sizeof(Keyword::keywords[0]); ++i) {
        if (sym == Keyword::keywords[i]) {
          curr_token = std::make_unique<Token>(Keyword{static_cast<Keyword::Kind>(i)});
          return;
        }
      }
    } while (std::ispunct(last_char));

    for (size_t i = 0; i < sizeof(Keyword::keywords) / sizeof(Keyword::keywords[0]); ++i) {
      if (sym == Keyword::keywords[i]) {
        curr_token = std::make_unique<Token>(Keyword{static_cast<Keyword::Kind>(i)});
        return;
      }
    }
    curr_token = std::make_unique<Token>(Unknown{last_char});
    return;
  }


  // EOF
  if (last_char == EOF) {
    curr_token = std::make_unique<Token>(Eof{});
    return;
  }

  // unknown
  curr_token = std::make_unique<Token>(Unknown{last_char});
}

}