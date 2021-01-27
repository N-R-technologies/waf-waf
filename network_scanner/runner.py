from .loader import Loader


class Runner:
    _loader = Loader()

    def execute_operation(self, loading_str, color, operation_to_run, *args):
        """
        :param loading_str: the string represent when loading
        :param color: the color of the loading
        :param operation_to_run: pointer to the function to run
        :param args: the arguments for the function
        :type loading_str: str
        :type color: class color
        :type operation_to_run: class function
        :type args: tuple
        :return: the return type of the function to operate
        """
        self._loader.start_loading(loading_str, color)
        operation_output = operation_to_run(*args)
        self._loader.stop_loading()
        return operation_output
