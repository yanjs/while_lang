#include "ast.hpp"
#include "lexer.hpp"
#include <cmath>
#include <map>
#include <vector>
#include <algorithm>

namespace wl {

const std::map<Keyword::Kind, size_t> precedence = {
  {Keyword::Kind::Or, 10},
  {Keyword::Kind::And, 20},
  {Keyword::Kind::Lt, 30},
  {Keyword::Kind::Le, 30},
  {Keyword::Kind::Gt, 30},
  {Keyword::Kind::Ge, 30},
  {Keyword::Kind::Eq, 30},
  {Keyword::Kind::Neq, 30},
  {Keyword::Kind::Plus, 40},
  {Keyword::Kind::Minus, 40},
  {Keyword::Kind::Mul, 50},
  {Keyword::Kind::Div, 50},
  {Keyword::Kind::Mod, 50},
};

static void assert_true(bool b, std::string msg) {
  if (!b) {
    throw ParserError(msg);
  }
}

static bool is_keyword_of_kind(const Token& k, Keyword::Kind kind) {
  return std::holds_alternative<Keyword>(k) && std::get<Keyword>(k).kind == kind;
}

static bool is_identifier(const Token& k) { return std::holds_alternative<Identifier>(k); }

double State::operator[](const str& name) const {
  if (m_variables.find(name) == m_variables.end()) {
    return 0;
  }
  return m_variables.at(name);
}
double &State::operator[](const str& name) { return m_variables[name]; }
void State::add_function(const FuncDefAST* f) { m_functions[f->get_name()] = f; }
const FuncDefAST* State::get_function(const str& name) const {
  auto it = m_functions.find(name);
  if (it == m_functions.end()) {
    return nullptr;
  }
  return it->second;
}
void State::print() const {
  for (const auto& [name, value] : m_variables) {
    std::cout << name << " == " << value << std::endl;
  }
}

VarAST::VarAST(const str& n) : name(n) {}
set<str> VarAST::get_vars() const { return {name}; }
double VarAST::eval(const State& s) const { return s[name]; }
str VarAST::get_name() const { return name; }

NumConstAST::NumConstAST(double v) : value(v) {}
set<str> NumConstAST::get_vars() const { return {}; }
double NumConstAST::eval(const State& s) const { return value; }

UnaryExpAST::UnaryExpAST(kind op, ptr<ExpAST> rhs) : op(op), rhs(std::move(rhs)) {}
set<str> UnaryExpAST::get_vars() const { return rhs->get_vars(); }
double UnaryExpAST::eval(const State& s) const {
  auto v = rhs->eval(s);
  switch (op) {
  case kind::Minus:
    return -v;
  case kind::Not:
    return !v;
  default:
    throw ParserError("Unknown operator");
  }
}

BinaryExpAST::BinaryExpAST(kind op, ptr<ExpAST> l, ptr<ExpAST> r)
  : op(op), lhs(std::move(l)), rhs(std::move(r)) {}
set<str> BinaryExpAST::get_vars() const {
  auto result = lhs->get_vars();
  auto r = rhs->get_vars();
  result.insert(r.begin(), r.end());
  return result;
}
double BinaryExpAST::eval(const State& s) const {
  auto l = lhs->eval(s);
  auto r = rhs->eval(s);
  switch (op) {
  case kind::Plus:
    return l + r;
  case kind::Minus:
    return l - r;
  case kind::Mul:
    return l * r;
  case kind::Div:
    return l / r;
  case kind::Mod:
    return std::fmod(l, r);
  case kind::And:
    return l && r;
  case kind::Or:
    return l || r;
  case kind::Lt:
    return l < r;
  case kind::Le:
    return l <= r;
  case kind::Gt:
    return l > r;
  case kind::Ge:
    return l >= r;
  case kind::Eq: 
    return l == r;
  case kind::Neq:
    return l != r;
  default:
    throw ParserError("Unknown operator");
  }
}

CallAST::CallAST(const str &n, vec<ptr<ExpAST>> a)
  : name(n), args(std::move(a)) {}
set<str> CallAST::get_vars() const {
  set<str> result{name};
  for (const auto& arg : args) {
    result.insert(arg->get_vars().begin(), arg->get_vars().end());
  }
  return result;
}
double CallAST::eval(const State& s) const {
  auto func_def_ast = s.get_function(name);
  if (!func_def_ast) {
    throw ParserError("Unknown function: " + name);
  }
  if (args.size() != func_def_ast->get_params().size()) {
    throw ParserError("Wrong number of arguments for function: " + name);
  }
  auto state = s;
  for (size_t i = 0; i < args.size(); i++) {
    state[func_def_ast->get_params()[i]] = args[i]->eval(s);
  }
  func_def_ast->get_body()->run(state);
  auto result = state["ret"];
  return result;
}

AsgnStmtAST::AsgnStmtAST(ptr<VarAST> v, ptr<ExpAST> e)
  : var(std::move(v)), expr(std::move(e)) {}
set<str> AsgnStmtAST::get_vars() const {
  auto vars = expr->get_vars();
  vars.insert(var->get_name());
  return vars;
}
State &AsgnStmtAST::run(State& s) const {
  auto v = expr->eval(s);
  s[var->get_name()] = v;
  return s;
}

set<str> SkipStmtAST::get_vars() const { return {}; }
State &SkipStmtAST::run(State& s) const { return s; }

SeqStmtAST::SeqStmtAST(ptr<StmtAST> l, ptr<StmtAST> r)
  : lhs(std::move(l)), rhs(std::move(r)) {}
set<str> SeqStmtAST::get_vars() const {
  auto result = lhs->get_vars();
  auto r = rhs->get_vars();
  result.insert(r.begin(), r.end());
  return result;
}
State &SeqStmtAST::run(State& s) const {
  State& s2 = lhs->run(s);
  State& s3 = rhs->run(s2);
  return s3;
}

IfStmtAST::IfStmtAST(ptr<ExpAST> c, ptr<StmtAST> t, ptr<StmtAST> e)
  : cond(std::move(c)), then_stmt(std::move(t)), else_stmt(std::move(e)) {}
set<str> IfStmtAST::get_vars() const {
  auto result = cond->get_vars();
  auto r = then_stmt->get_vars();
  result.insert(r.begin(), r.end());
  r = else_stmt->get_vars();
  result.insert(r.begin(), r.end());
  return result;
}
State &IfStmtAST::run(State& s) const {
  if (cond->eval(s)) {
    then_stmt->run(s);
  } else {
    else_stmt->run(s);
  }
  return s;
}

WhileStmtAST::WhileStmtAST(ptr<ExpAST> c, ptr<StmtAST> s)
  : cond(std::move(c)), stmt(std::move(s)) {}
set<str> WhileStmtAST::get_vars() const {
  auto result = cond->get_vars();
  auto r = stmt->get_vars();
  result.insert(r.begin(), r.end());
  return result;
}
State &WhileStmtAST::run(State& s) const {
  while (cond->eval(s)) {
    stmt->run(s);
  }
  return s;
}

FuncDefAST::FuncDefAST(str n, vec<str> p, ptr<StmtAST> b)
  : name(n), params(std::move(p)), body(std::move(b)) {
  auto unique_params = set<str>(params.begin(), params.end());
  if (unique_params.size() != params.size()) {
    throw ParserError("Duplicate parameter names");
  }
}
set<str> FuncDefAST::get_vars() const {
  auto body_vars = body->get_vars();
  auto param_vars = set<str>(params.begin(), params.end());
  param_vars.insert(name);
  auto result = set<str>{};
  std::set_difference(
    body_vars.begin(), body_vars.end(),
    param_vars.begin(), param_vars.end(),
    std::inserter(result, result.begin()));
  return result;
}
State &FuncDefAST::run(State& s) const {
  s.add_function(this);
  return s;
}
str FuncDefAST::get_name() const { return name; }
const vec<str>& FuncDefAST::get_params() const { return params; }
const StmtAST* FuncDefAST::get_body() const {
  auto b = body.get();
  if (!b) {
    throw ParserError("Function body is empty");
  }
  return b;
}

ParserError::ParserError(const std::string& what) : std::runtime_error(what) {}

static ptr<ExpAST> parse_paren_exp(Lexer &lexer) {
  auto lparen = lexer.get_token();
  assert_true(is_keyword_of_kind(*lparen, Keyword::Kind::LParen),
    "Error in source code, this should be '('");
  auto exp = parse_exp(lexer);
  assert_true(!!exp, "Expect an expression");
  auto rparen = lexer.get_token();
  assert_true(is_keyword_of_kind(*rparen, Keyword::Kind::RParen),
    "Expect ')'");
  return exp;
}

static std::optional<size_t> get_binary_op_precedence(Keyword::Kind kind) {
  auto it = precedence.find(kind);
  if (it == precedence.end()) {
    return std::nullopt;
  }
  return it->second;
}

static ptr<ExpAST> parse_left_largest_exp(Lexer &lexer, ptr<ExpAST> &&left_most) {
  vec<ptr<ExpAST>> exps{};
  exps.push_back(std::move(left_most));
  vec<Keyword::Kind> ops{};
  size_t curr_precedence = 0;

  do {
    auto maybe_op = lexer.peek_token();
    if (!std::holds_alternative<Keyword>(*maybe_op)) {
      break;
    }
    auto op = std::get<Keyword>(*maybe_op);
    auto op_precedence = get_binary_op_precedence(op.kind);
    if (!op_precedence || op_precedence.value() <= curr_precedence) {
      break;
    }
    curr_precedence = op_precedence.value();
    auto op_token = lexer.get_token();
    assert_true(std::holds_alternative<Keyword>(*op_token),
      "Error in source code, should be a binary operator");
    ops.push_back(op.kind);

    auto curr_exp = parse_single_exp(lexer);
    assert_true(!!curr_exp, "Expect an expression on rhs of binary operator");
    exps.push_back(std::move(curr_exp));
  } while (true);

  assert_true(exps.size() == ops.size() + 1,
    "Error in source code, there should be one more expression than operators");

  auto rhs = std::move(exps.back());
  exps.pop_back();

  if (ops.empty()) {
    return rhs;
  }

  for (auto it = ops.rbegin(); it != ops.rend(); ++it) {
    auto op = *it;
    auto lhs = std::move(exps.back());
    exps.pop_back();
    rhs = std::make_unique<BinaryExpAST>(op, std::move(lhs), std::move(rhs));
  }
  return rhs;
}

static ptr<ExpAST> parse_exp(Lexer &lexer) {
    auto leftmost_exp = parse_single_exp(lexer);
    assert_true(!!leftmost_exp, "Expect an expression on lhs of operator");

    while (true) {
      auto old_underlying = leftmost_exp.get();
      auto maybe_new_exp = parse_left_largest_exp(lexer, std::move(leftmost_exp));

      if (old_underlying == maybe_new_exp.get()) {
        return maybe_new_exp;
      }
      leftmost_exp = std::move(maybe_new_exp);
    }

    return leftmost_exp;
}

static vec<ptr<ExpAST>> parse_paren_args(Lexer &lexer) {
  auto should_be_lparen = lexer.get_token();
  assert_true(is_keyword_of_kind(*should_be_lparen, Keyword::Kind::LParen),
    "Error in source code, this should be '('");

  auto maybe_rparen = lexer.peek_token();
  if (is_keyword_of_kind(*maybe_rparen, Keyword::Kind::RParen)) {
    lexer.get_token();
    return {};
  }

  vec<ptr<ExpAST>> args{};
  while (true) {
    auto arg = parse_exp(lexer);
    assert_true(!!arg, "Expect an expression in paren_args");
    args.push_back(std::move(arg));

    auto maybe_comma_or_rparen = lexer.peek_token();
    assert_true(is_keyword_of_kind(*maybe_comma_or_rparen, Keyword::Kind::Comma)
      || is_keyword_of_kind(*maybe_comma_or_rparen, Keyword::Kind::RParen),
      "Expect ',' or ')'");

    if (is_keyword_of_kind(*maybe_comma_or_rparen, Keyword::Kind::Comma)) {
      lexer.get_token();
    } 
    auto maybe_rparen_or_var = lexer.peek_token();
    if (is_keyword_of_kind(*maybe_rparen_or_var, Keyword::Kind::RParen)) {
      lexer.get_token();
      return args;
    }
  }
}

static ptr<ExpAST> parse_single_exp(Lexer &lexer) {
  auto token = lexer.peek_token();
  return std::visit([&](auto&& token) -> ptr<ExpAST> {
    using T = std::decay_t<decltype(token)>;
    if constexpr (std::is_same_v<T, Keyword>) {
      ptr<Token> temp_;
      switch (token.kind) {
        case Keyword::Kind::True:
          temp_ = lexer.get_token();
          return std::make_unique<NumConstAST>(1);
        case Keyword::Kind::False:
          temp_ = lexer.get_token();
          return std::make_unique<NumConstAST>(0);
        case Keyword::Kind::Not: {
          temp_ = lexer.get_token();
          auto bexp = parse_single_exp(lexer);
          assert_true(!!bexp, "Expect an expression on rhs of 'not'");
          return std::make_unique<UnaryExpAST>(Keyword::Kind::Not, std::move(bexp));
        }
        case Keyword::Kind::LParen:
          return parse_paren_exp(lexer);
        default:
          throw ParserError{"Expect 'true', 'false', 'not', or '('"};
      }
    } else if constexpr (std::is_same_v<T, Identifier>) {
      auto temp_ = lexer.get_token();
      auto maybe_lparen = lexer.peek_token();
      if (!is_keyword_of_kind(*maybe_lparen, Keyword::Kind::LParen)) {
        return std::make_unique<VarAST>(token.name);
      }
      auto args = parse_paren_args(lexer);
      return std::make_unique<CallAST>(token.name, std::move(args));
    } else if constexpr (std::is_same_v<T, Number>) {
      auto temp_ = lexer.get_token();
      auto val = token.val;
      return std::make_unique<NumConstAST>(val);
    }

    throw ParserError{"Expect 'true', 'false', 'not', '(', identifier, or number"};
    return ptr<ExpAST>{};
  }, *token);
}

static ptr<StmtAST> parse_while_stmt(Lexer &lexer) {
  auto while_keyword = lexer.get_token();
  assert_true(is_keyword_of_kind(*while_keyword, Keyword::Kind::While),
    "Error in source code, this should be 'while'");

  auto cond = parse_exp(lexer);
  assert_true(!!cond, "Expect an expression in while condition");

  auto do_keyword = lexer.get_token();
  assert_true(is_keyword_of_kind(*do_keyword, Keyword::Kind::Do),
    "Expect 'do'");

  auto stmt = parse_stmt(lexer);
  assert_true(!!stmt, "Expect a statement in while body");

  auto od_keyword = lexer.get_token();
  assert_true(is_keyword_of_kind(*od_keyword, Keyword::Kind::Od),
    "Expect 'od'");

  return std::make_unique<WhileStmtAST>(std::move(cond), std::move(stmt));
}

static ptr<StmtAST> parse_if_stmt(Lexer &lexer) {
  auto if_keyword = lexer.get_token();
  assert_true(is_keyword_of_kind(*if_keyword, Keyword::Kind::If),
    "Error in source code, this should be 'if'");

  auto cond = parse_exp(lexer);
  assert_true(!!cond, "Expect an expression in if condition");

  auto then_keyword = lexer.get_token();
  assert_true(is_keyword_of_kind(*then_keyword, Keyword::Kind::Then),
    "Expect 'then'");

  auto then_stmt = parse_stmt(lexer);
  assert_true(!!then_stmt, "Expect a statement in then branch");

  auto else_keyword = lexer.get_token();
  assert_true(is_keyword_of_kind(*else_keyword, Keyword::Kind::Else),
    "Expect 'else'");

  auto else_stmt = parse_stmt(lexer);
  assert_true(!!else_stmt, "Expect a statement in else branch");

  auto fi_keyword = lexer.get_token();
  assert_true(is_keyword_of_kind(*fi_keyword, Keyword::Kind::Fi),
    "Expect 'fi'");

  return std::make_unique<IfStmtAST>(
    std::move(cond),
    std::move(then_stmt),
    std::move(else_stmt));
}

static ptr<FuncDefAST> parse_func_def(Lexer &lexer) {
  auto func_keyword = lexer.get_token();
  assert_true(is_keyword_of_kind(*func_keyword, Keyword::Kind::Func),
    "Error in source code, this should be 'func'");

  auto name = lexer.get_token();
  assert_true(is_identifier(*name), "Expect an identifier");
  auto name_str = std::get<Identifier>(*name).name;

  auto maybe_lparen = lexer.peek_token();
  assert_true(is_keyword_of_kind(*maybe_lparen, Keyword::Kind::LParen),
    "Expect '('");

  auto args = parse_paren_args(lexer);
  vec<str> arg_names{};

  for (auto &arg : args) {
    if (auto maybe_var = dynamic_cast<VarAST*>(arg.get())) {
      if (maybe_var->get_name() == name_str) {
        throw ParserError{"Function name cannot be the same as the variable name"};
      }
      arg_names.push_back(maybe_var->get_name());
    } else {
      throw ParserError{"Expect an identifier as a function argument"};
    }
  }

  auto body = parse_stmt(lexer);
  assert_true(!!body, "Expect a statement in function body");
  auto should_be_cnuf = lexer.get_token();
  assert_true(is_keyword_of_kind(*should_be_cnuf, Keyword::Kind::Cnuf),
    "Expect 'cnuf'");
  return std::make_unique<FuncDefAST>(name_str, std::move(arg_names), std::move(body));
}

static ptr<StmtAST> parse_single_stmt(Lexer &lexer) {
  const auto token = lexer.peek_token();

  return std::visit([&](auto&& token) -> ptr<StmtAST> {
    using T = std::decay_t<decltype(token)>;
    if constexpr (std::is_same_v<T, Keyword>) {
      auto k = token.kind;
      switch (k) {
      case Keyword::Kind::If:{
        auto if_stmt = parse_if_stmt(lexer);
        assert_true(!!if_stmt, "Error in source code, should get an if statement");
        return if_stmt;
      }
      case Keyword::Kind::While: {
        auto while_stmt = parse_while_stmt(lexer);
        assert_true(!!while_stmt, "Error in source code, should get a while statement");
        return while_stmt;
      }
      case Keyword::Kind::Skip: {
        lexer.get_token();
        return std::make_unique<SkipStmtAST>();
      }
      case Keyword::Kind::Func: {
        auto func_def = parse_func_def(lexer);
        return func_def;
      }
      default:
        throw ParserError{"Expect a statement, maybe after ';'"};
      }
    } else if constexpr (std::is_same_v<T, Identifier>) {
      auto token = std::get<Identifier>(*lexer.get_token());
      auto var = std::make_unique<VarAST>(token.name);

      auto asgn_op = lexer.get_token();
      assert_true(is_keyword_of_kind(*asgn_op, Keyword::Kind::Asgn), "Expect ':='");

      auto expr = parse_exp(lexer);
      assert_true(!!expr, "Expect an expression on rhs of ':='");

      return std::make_unique<AsgnStmtAST>(std::move(var), std::move(expr));
    } else {
      throw ParserError{"Expect statement"};
      return ptr<StmtAST>();
    }
  }, *token);

}

ptr<StmtAST> parse_stmt(Lexer &lexer) {
  auto stmt = parse_single_stmt(lexer);
  assert_true(!!stmt, "Expect a statement");

  auto maybe_seq = lexer.peek_token();
  if (is_keyword_of_kind(*maybe_seq, Keyword::Kind::Seq)) {
    lexer.get_token();
    auto stmt2 = parse_stmt(lexer);
    assert_true(!!stmt2, "Expect a second statement after ';'");
    return std::make_unique<SeqStmtAST>(std::move(stmt), std::move(stmt2));
  }
  return stmt;
}

} // namespace wl