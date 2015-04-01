import os
import json
import types

__all__ = ['FileProxy']


class FileProxyResolver(type):
    """
    Metaclass which allows FileProxy to be called like a function to assign proxy attributes
    """

    def __call__(cls, *args, **kwargs):
        if len(args) == 1:
            expression = args[0]
            if isinstance(expression, types.FunctionType):
                expression._fileproxy = True
            elif isinstance(expression, basestring):
                key = expression
                expression = lambda cls, env: env[key]
                expression._fileproxy = True
            expression = classmethod(expression)
            return expression
        return super(FileProxyResolver, cls).__call__(*args)


class FileProxy(type):
    """
    Metaclass which allows class attributes to be lazy loaded from a serialized file

    ~/environment.json contents
    {
        "SETTING1_A": "value1a",
        "SETTING1_B": "value1b",
        "SETTING2": "value2"
    }

    @FileProxy.json('~/environment.json')
    class ExampleConfig(object):
        __metaclass__ = FileProxy

        SETTING1 = FileProxy(lambda cls, env: dict(A=env['SETTING1_A'], B=env['SETTING1_B']))
        SETTING2 = FileProxy('SETTING2')

    ExampleConfig.SETTING1
        { 'A': 'value1a', 'B': 'value1b' }
    ExampleConfig.SETTING2
        'value2'
    """

    __metaclass__ = FileProxyResolver

    def load_data(cls):
        path = os.path.expanduser(os.path.expandvars(cls._filepath))
        with open(path, 'r') as f:
            cls._data = cls._dataproxy(f)

    def evaluate_proxy(cls, expression):
        if not hasattr(cls, '_data'):
            cls.load_data()
        return expression(cls._data)

    def __getattribute__(cls, item):
        value = type.__getattribute__(cls, item)
        if getattr(value, '_fileproxy', False):
            value = cls.evaluate_proxy(value)
            setattr(cls, item, value)
        return value

    @classmethod
    def json(mcs, path):
        """
        Specify a json file as the proxy backing
        """

        def inner(wrapped):
            wrapped._filepath = path
            wrapped._dataproxy = classmethod(lambda cls, f: json.loads(f.read()))
            return wrapped
        return inner
