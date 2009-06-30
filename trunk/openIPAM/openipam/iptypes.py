import IPy
import types

class IP(IPy.IP):
	def __binary_op(self, a):
		ver = self.version()

		if type(a) == types.StringType:
			a = IP(a)
		if hasattr(a,'prefixlen'):
			a_prefix = a.prefixlen()
			if ver != a.version():
				raise TypeError('Binary operations do not support addresses from different families: %s, %s' % (self, a))
		else:
			a_prefix = -1

		if self.prefixlen() == a_prefix:
			prefixlen=self.prefixlen()
		else:
			if ver == 4:
				prefixlen = 32
			elif ver == 6:
				prefixlen = 128
			else:
				raise TypeError('Do not understand IP type! (ver: %s)' % ver)
		return prefixlen

	def __and__(self, a):
		prefixlen = self.__binary_op(a)
		if hasattr(a,'int'):
			v = IP( self.int() & a.int() )
		else:
			v = IP( self.int() & a )
		v._prefixlen = prefixlen
		return v

	def __or__(self, a):
		prefixlen = self.__binary_op(a)
		if hasattr(a,'int'):
			v = IP( self.int() | a.int() )
		else:
			v = IP( self.int() | a )
		v._prefixlen = prefixlen
		return v

	def __xor__(self, a):
		prefixlen = self.__binary_op(a)
		if hasattr(a,'int'):
			v = IP( self.int() ^ a.int() )
		else:
			v = IP( self.int() ^ a )
		v._prefixlen = prefixlen
		return v

	def __not__(self):
		prefixlen=self.prefixlen()
		v = IP( ~self.int() )
		v._prefixlen = prefixlen
		return v

	def family(self):
		return self.version()




