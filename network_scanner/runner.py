from .loader import Loader


class Runner:
    _loader = Loader()

    def execute_operation(self, loading_str, color, operation_to_run, *args):
        self._loader.start_loading(loading_str, color)
        operation_output = operation_to_run(*args)
        self._loader.stop_loading()
        return operation_output
