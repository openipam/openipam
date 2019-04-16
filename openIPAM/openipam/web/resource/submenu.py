import types

class submenu:
	''''''
	def __init__(self, values, links, title='', selected=None):
		'''Takes a set of links and values and formats them as a submenu for the leftnav 
			@param links: tuple of strings to be used as the URI  (so, links will be <li><a href="HERE"></a></li>)
			@param values: tuple of strings for the link name (so, values will be <li><a href="">HERE</a></li>)
			@param title: the text for the first li that will have the "title" class applied (no link)
			@param selected: the name of the selected element ... this will have the "active" class applied
		'''
		
		# make sure links and titles are both tuples
		if (type(values) is not tuple) or (type(links) is not tuple) :
			raise Exception("Values or links passed to submenu is not a tuple")
				
		self.__values = values
		self.__links = links
		self.__title = title
		self.__selected = selected
		
	#-----------------------------------------------------------------
	
	def __str__( self ):
		
		text = []
		text.append('<ul id="submenu">')
		text.append('<li id="title">%s</li>' % self.__title)
		
		counter = 0
		for link in self.__links:
			if self.__values[counter] == self.__selected:
				text.append('<li id="active"><a href="%s">%s</a></li>' % (link, self.__values[counter]))
			else:
				text.append('<li><a href="%s">%s</a></li>' % (link, self.__values[counter]))
			counter += 1
			
		text.append('</ul>')
		return ''.join(text)
	
class OptionsSubmenu:
	'''
	A submenu for toggleable options that are not actions,
	like Show All Hosts or Show Expired Hosts
	'''
	def __init__(self, values, links, selected, title=''):
		'''Takes a set of links and values and formats them as a submenu for the leftnav 
			@param links: tuple of strings to be used as the URI  (so, links will be <li><a href="HERE"></a></li>)
			@param values: tuple of strings for the link name (so, values will be <li><a href="">HERE</a></li>)
			@param selected: a list of booleans that is as long as links, each option will be "on" if True, "off" if false
			@param title: the text for the first li that will have the "title" class applied (no link)
		'''
		
		# make sure links and titles are both tuples
		if (type(values) is not tuple) or (type(links) is not tuple) or (type(selected) is not tuple):
			raise Exception("Values or links passed to submenu is not a tuple")
		
		self.__values = values
		self.__links = links
		self.__title = title
		self.__selected = selected
		
	#-----------------------------------------------------------------
	
	def __str__( self ):
		
		text = []
		text.append('<ul id="submenu" class="options">')
		text.append('<li id="title">%s</li>' % self.__title)
		
		counter = 0
		for link in self.__links:
			if self.__selected[counter]:
				#text.append('<li id="active"><a href="%s">%s</a></li>' % (link, self.__values[counter][1]))
				text.append('<li><a href="%s">%s</a></li>' % (link, self.__values[counter][1]))
			else:
				text.append('<li><a href="%s">%s</a></li>' % (link, self.__values[counter][0]))
			counter += 1
			
		text.append('</ul>')
		return ''.join(text)
