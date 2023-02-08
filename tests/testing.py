from text_formatting import red, green, bold, italic, truncate, underline
from typing import Callable

class TestFailure(Exception):
    def __init__(self, in_args: tuple, success_condition: str, output_target: any, actual_output: any):
        self.in_args = in_args
        self.output_target = output_target
        self.actual_output = actual_output
        self.message = red(bold("Test Failed!")) + '\n'
        self.message += f"\tInput: {bold(truncate(str(in_args), 70))}\n"
        self.message += f"\tExpected Output {success_condition}: {bold(truncate(str(output_target), 70))}\n"
        self.message += f"\tGot Instead: {bold(truncate(str(actual_output), 70))}"
        super().__init__(f"Test failed")

def get_test_function(function: Callable, success_condition: str, *args) -> Callable:

    if success_condition == "eq":
        def test(in_args, output_target):
            try:
                result = function(*in_args)
            except Exception as e:
                raise TestFailure(in_args, success_condition, output_target, e.message if hasattr(e, "message") else str(e))
            if result != output_target:
                raise TestFailure(in_args, success_condition, output_target, result)

    elif success_condition == "ne":
        def test(in_args, banned_output):
            try:
                result = function(*in_args)
            except Exception as e:
                raise TestFailure(in_args, success_condition, banned_output, e.message if hasattr(e, "message") else str(e))
            if result == banned_output:
                raise TestFailure(in_args, success_condition, banned_output, result)

    elif success_condition == "raises":
        target_exception = args[0]
        def test(in_args, _ = None):
            try:
                result = function(*in_args)
            except target_exception:
                return
            except Exception as e:
                raise TestFailure(in_args, success_condition, target_exception, e.message if hasattr(e, "message") else str(e))
            raise TestFailure(in_args, success_condition, target_exception, result)
    else:
        raise Exception("Invalid test condition")
    return test


class Test:
    def __init__(self, name: str, function: Callable, tests: list[tuple[tuple, any]], success_condition: str, *args):
        self.test_function = get_test_function(function, success_condition, *args)
        self.tests = tests
        self.name = name
        self.failed_tests = []

    def run(self):
        for test in self.tests:
            in_args, out_val = test
            try:
                self.test_function(in_args, out_val)
            except TestFailure as failure:
                print(failure.message)
                self.failed_tests.append(failure)

class TestSet:
    def __init__(self, name: str, *tests):
        self.name = name
        self.tests = tests
        self.failures = {}

    def run_all(self):
        print(bold(underline(f"Starting Test Set: {self.name}")))
        print(bold(f"Running {len(self.tests)} unit tests..."))
        for test in self.tests:
            self.failures[test.name] = []
            print(f"Running unit test {bold(test.name)}...")
            test.run()
            if test.failed_tests:
                print(red("One or more test cases failed..."))
                for fail in test.failed_tests:
                    self.failures[test.name].append(fail)
            else:
                print(green("All test cases passed successfully!"))
        print("\nAll unit tests completed. Here is a summary of the results:")
        for test in self.tests:
            print(f"\t{test.name}: ", end = '')
            fail_rate = 100 * len(self.failures[test.name]) / len(test.tests)
            pass_rate = 100 - fail_rate
            if pass_rate == 100:
                print(green("100%!"))
            elif pass_rate > 50:
                print(pass_rate)
            else:
                print(red(pass_rate))

