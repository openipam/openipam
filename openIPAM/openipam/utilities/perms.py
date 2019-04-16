"""
Permissions objects

WRITEME, ELDON
"""

import types

class PermsList( object ):
	def __init__( self, perms_dicts ):
		for d in perms_dicts:
			setattr( self, d['name'], Perms(d['id']) )

class Perms( object ):
	def __init__( self, bits ):
		self.__bits=None
		self.__integer=None
		self.__len = 8 # bits
		
		if type(bits) == bytes:
			if len( bits ) != self.__len:
				raise Exception("wrong length: '%s' is not %s characters" % (bits, self.__len) )
			self.__bits = bits
			int(self)
		elif type(bits) == int:
			self.__integer = bits
			str(self)
		elif type(bits) == type(self):
			self.__bits = str(bits)
			int(self)
		else:
			raise Exception("Unrecognized type for permissions object ... type was: %s" % str(type(bits)))
		
	def __int__( self ):
		if  self.__integer == None:
			if not self.__bits:
				raise Exception("python must be broken if it let you get here")
			val = 0
			for i in range(self.__len):
				if self.__bits[-(i+1)] == '1':
					val += 2**i
			self.__integer = val
		return self.__integer
	
	def __repr__( self ):
		return "B'%s'" % str(self)
	
	def __str__( self ):
		if not self.__bits:
			if self.__integer == None:
				raise Exception("Perms without bits/integer?")
			if self.__integer > 2**(self.__len + 1) - 1:
				raise Exception("Bad range")
			
			bits = ['0','0','0','0','0','0','0','0']
			for i in range(8):
				if (self.__integer >> (self.__len-i-1)) & 1:
					bits[i] = '1'
			self.__bits = ''.join(bits)
		return self.__bits
	
	def __eq__(self, a ):
		if type(a) is type(None):
			return False
		return int(self) == int(Perms(a))
	
	def __ne__(self, a ):
		if type(a) is type(None):
			return True
		return int(self) != int(Perms(a))
	
	def __and__( self, a ):
		if type(a) is bytes:
			a = Perms(a)
		return Perms( int(self) & int(Perms(a)) )
	
	def __or__( self, a ):
		if type(a) is bytes:
			a = Perms(a)
		return Perms( int(self) | int(Perms(a)) )

