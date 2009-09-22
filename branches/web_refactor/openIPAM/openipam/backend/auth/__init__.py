from openipam.config import auth

class DictWrapper( object ):
	def __init__( self, d ):
		self.__vals = d
	def __getattr__( self, name ):
		return self.__vals[name]

sources = DictWrapper( auth.dbi.get_auth_sources() )

