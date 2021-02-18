from .loader import Loader


class Runner:
    _loader = Loader()

    def execute_operation(self, loading_str, color, operation_to_run, *args):
        """
        This function will start and stop the loading animation,
        and will execute the given function with its given parameters
        :param loading_str: the string to display on the loading animation
        :param color: the color of the loaded string
        :param operation_to_run: a pointer to the executed function
        :param args: the packed parameters of the executed function
        :type loading_str: string
        :type color: Color
        :type operation_to_run: function
        :type args: tuple
        :return: the result of the executed function
        :rtype: string, boolean or None (depends on which function is being executed)
        """
        self._loader.start_loading(loading_str, color)
        operation_output = operation_to_run(*args)
        self._loader.stop_loading()
        return operation_output
