#include "lexer.hpp"
#include "ast.hpp"
#include "codegen.hpp"
#include <string>
#include <sstream>
#include <fstream>
#include <functional>

using namespace wl;

void assert_true(bool b, std::string msg = "") {
  if (!b) {
    throw std::runtime_error("assertion failed: " + msg);
  }
}

void assert_exception(std::function<void()> f, std::string msg = "") {
  try {
    f();
  } catch (std::runtime_error& _) {
    return;
  }
  throw std::runtime_error("assertion failed: " + msg);
}

void test_lexer() {
  auto test_input = std::istringstream{"if bad"};

  Lexer lexer{test_input};
  auto t = lexer.get_token();
  assert_true(std::holds_alternative<Keyword>(*t), "if should be keyword");

  auto t2 = lexer.get_token();
  assert_exception([&]() {
    assert_true(std::holds_alternative<Keyword>(*t2));
  }, "bad should not be keyword");
}

void test_ast(std::string filename = "test.while") {
  std::ifstream f{filename};
  Lexer lexer{f};

  try {
    auto stmt = parse_stmt(lexer);
    assert_true(std::holds_alternative<Eof>(*lexer.peek_token()), "Expect end of file");
    auto state = State{};
    stmt->run(state);
    std::cout << "State after execution: " << std::endl;
    state.print();
    std::cout << "End State" << std::endl;
  } catch (std::runtime_error& e) {
    std::cout << e.what() << std::endl;
  }

}

void test_codegen(std::string filename = "test.while") {
  std::ifstream f{filename};
  Lexer lexer{f};

  try {
    auto stmt = parse_stmt(lexer);
    assert_true(std::holds_alternative<Eof>(*lexer.peek_token()), "Expect end of file");

    CodegenContext ctx;
    double return_value = ctx.codegen_top_level(*stmt);
    std::cout << "Return value: " << return_value << std::endl;
  } catch (std::runtime_error& e) {
    std::cout << e.what() << std::endl;
  }
  std::cout << "End llvm code gen." << std::endl;
}
    

int main(int argc, char **argv) {
  test_lexer();
  if (argc > 1) {
    test_ast(argv[1]);
    test_codegen(argv[1]);
  } else {
    test_ast();
    test_codegen();
  }
  std::cerr << "Success" << std::endl;
}