We have adopted and follow these practices for all code in openIPAM:

## Variable and function names ##

Follow C-style syntax:

```
get_hosts( ... )
__check_permissions( ... )
valid_types = ( types.ListType )
```


## Docstrings ##

Classes and functions should have detailed docstrings related to the functionality of the method. Specify `@params` for all arguments, `@return` if the function returns, and `@raise` for conditions under which the function will error.

## Functions ##

```
def del_host_attribute(self, aid):
	'''
	Delete an attribute and all data associated with it for all hosts
	@param aid: the database attribute id
	'''
	
	...
```

Never use a list or a dictionary as a default argument:

```
>>> def example( arg=[0] ):
...    print arg
...    arg.append( arg[-1] + 1 )
... 
>>> example()
[0]
>>> example()
[0, 1]
>>> example()
[0, 1, 2]
```

Do this instead:
```
>>> def example( arg=None ):
...    if not arg:
...       arg = [0]
...    print arg
...    arg.append( arg[-1] + 1 )
... 
>>> example()
[0]
>>> example()
[0]
```

## Classes ##

Classes (just the class names, not an instantiated object) are camel-cased with a capital first letter:

```
class MainWebService(XMLRPCController, object):
	...
```