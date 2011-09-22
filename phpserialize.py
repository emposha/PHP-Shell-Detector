"""
 Class PHP_Serializer
 	Python to PHP serialize / unserialize class UTF8 compatible.
 This class converts php variables to python and vice versa.
 _____________________________________________

 PARSABLE PYTHON === > PHP VARIABLES:
	[ PYTHON TYPE ]		[ PHP TYPE ]
	dict		=== >	 	array
	list		=== >	 	array
	tuple		=== >	 	array
	class		=== >	 	class (*)
	string		=== >	 	string
	bool		=== >	 	boolean
	None		=== >	 	null
	int		=== >	 	int
	float		=== >	 	float
	long		=== >	 	float

 PARSABLE PHP === > PYTHON VARIABLES:
	[ PHP TYPE ]		[ PYTHON TYPE ]
	array		=== >	 	list if indexes are int
	array		=== >	 	dict if some index is not an int
	class		=== >	 	class (*)
	string		=== >	 	string
	boolean		=== >	 	bool
	null		=== >	 	None
	int		=== >	 	int
	float		=== >	 	float
	double		=== >	 	float

 (*) NOTE:
 Every Python class instance export only public parameters and unserializzation should be in two ways:
	1 - empty class if PHP_Serializer file is imported with every public parameter
	2 - same class without __init__ method but with every public parameter
 In these cases you should synchronize your unserialized variable using sync method
	php_serializer_var.sync(OriginalClass, unserializedVar)
 That will try to creates every method of unserializedVar.
 Any PHP serialized class requires the native PHP class to be used, then it's not a
 PHP => Python converter, it's just a usefull serilizer class for each
 compatible Py and PHP variable types.
 Class serializzation is actually beta, then use carefully.
 Sub classes are not supported, every class is created in this way: type(className, (), {})
 Lambda, Resources or other dedicated PHP/Python variables are not serializable.
 

 EXTRA NOTE:
 This class works in "optmist way", use try except when you serialize or unserialize some variable
 
 Exceptions:
	serialize	TypeError	variable is not serializable
	unserialize	ValueError	variable is not unserializable
 _____________________________________________

 EXAMPLE 1:
	php = PHP_Serializer(); // use PHP_Serializer(True); to enable UTF8 compatibility
	print php.unserialize(php.serialize(somevar))
	# should alert the original value of somevar

 EXAMPLE 2:
	from PHP_Serializer import PHP_Serializer
	phpser = PHP_Serializer(False)
       
	test = "every compatible var" # every type of var, phpser too
	stest = phpser.serialize(test)
	utest = phpser.unserialize(stest)
       
	print "\n".join([
	       "serialize\n	" + stest,
	       "unserialize\n	" + str(utest),
	       "same var\n	" + str(utest == test)
	])
	
	# same var should return False with objects (different instances)

 ---------------------------------------------
 @author		Andrea Giammarchi
 @site			www.devpro.it
 @date			2008/08/14
 @lastmod		2008/08/19 [SECURITY FIX: removed eval function and added className check ([a-zA-Z0-9_]+)]
 @version		0.1c
 @credits		Scott Hurring for some ideas  and his serialize project
			[http://www.hurring.com/code/python/serialize/]
			lists.python.it
"""

import types, re

class PHP_Serializer:
		
	UTF8 = False
	__c = 0
		
	def serialize(self, v):
		i = 0
		s = "N;"
		tmp = []
		vtype = type(v)
		if vtype is types.BooleanType:
			s = "b:%i;" % (v == 1)
		elif vtype is types.IntType:
			s = "i:%s;" % v
		elif vtype is types.FloatType or vtype is types.LongType:
			s = "d:%s;" % v
		elif vtype is types.StringType:
			s = "s:%i:\"%s\";" % (self.__slen(v), v)
		elif vtype is types.DictType:
			for key in v:
				if re.sub("^\-?[0-9]+$", "", key) == "" and str(int(key)) == key:
					s = self.serialize(int(key))
				else:
					s = self.serialize(key)
				if s[0] == "i" or s[0] == "s":
					tmp.append(s)
					tmp.append(self.serialize(v[key]))
					i = i + 1
			s = "a:%i:{%s}" % (i, "".join(tmp))
		elif  vtype is types.ListType or vtype is types.TupleType:
			for key in v:
				tmp.append(self.serialize(i))
				tmp.append(self.serialize(v[i]))
				i = i + 1
			s = "a:%i:{%s}" % (i, "".join(tmp))
		elif vtype is types.InstanceType:
			s = v.__class__.__name__
			tmp = self.__serializeClass(v)
			s = "".join(["O:", str(self.__slen(s)), ":\"", s, "\":", str(tmp[0]), ":{", tmp[1], "}"])
		if s == "N;" and not(vtype is types.NoneType):
			raise TypeError("Unsupported type: " + str(vtype))
		return s
	
	def sync(self, C, O):
		for key in C.__dict__:
			O.__class__.__dict__[key] = C.__dict__[key]
		O.__dict__.update()

	def unserialize(self, v, start = True):
		result = None
		tmpvar = None
		islist = True
		pos = 0
		tmp = []
		if start == True:
			self.__c = 0
		if v[self.__c] == "N":
			self.__c = self.__c + 2
		elif v[self.__c] == "b":
			result = v[self.__c + 2] == "1"
			self.__c = self.__c + 4
		elif v[self.__c] == "i":
			tmp.append(v.find(";", self.__c))
			pos = self.__c + 2
			self.__c = tmp[0] + 1
			result = int(v[pos:tmp[0]])
		elif v[self.__c] == "d":
			tmp.append(v.find(";", self.__c))
			pos = self.__c + 2
			self.__c = tmp[0] + 1
			result = float(v[pos:tmp[0]])
		elif v[self.__c] == "s":
			tmp.append(v.find(":", self.__c + 2))
			tmp.append(tmp[0] + 2)
			if self.UTF8:
				pos = self.__c + 2
				tmp.append(0)
				tmp.append(int(v[pos:tmp[0]]))
				while True:
					tmp[2] = tmp[2] + self.__slen(v[tmp[1]])
					tmp[1] = tmp[1] + 1
					if tmp[2] >= tmp[3]:
						pos = tmp[0] + 2 + tmp[2]
						self.__c = pos + 2
						result = v[(tmp[0] + 2):pos]
						break
			else:
				pos = self.__c + 2
				self.__c = tmp[1] + int(v[pos:tmp[0]])
				result = v[tmp[1]:self.__c]
				self.__c = self.__c + 2
		elif v[self.__c] == "a":
			pos = self.__c + 2
			tmp.append(v.find(":", pos))
			tmp.append(int(v[pos:tmp[0]]))
			self.__c = tmp[0] + 2
			result = {}
			for i in range(0, tmp[1]):
				tmpvar = self.unserialize(v, False)
				result[tmpvar] = self.unserialize(v, False)
				if not (type(tmpvar) is int) or tmpvar < 0:
					islist = False
			if islist:
				tmp.append([])
				for key in result:
					pos = len(tmp[2])
					while key > pos:
						tmp[2].append(None)
						pos = pos + 1
					tmp[2].append(result[key])
				result = tmp[2]
			self.__c = self.__c + 1
		elif v[self.__c] == "O":
			pos = v.find("\"", self.__c) + 1
			self.__c = v.find("\"", pos)
			tmp.append(v[pos:self.__c])
			self.__c = self.__c + 2
			if re.sub("^[a-zA-Z0-9_]+$", "", tmp[0]) == "":
				result = self.__unserializeClass(v, type(tmp[0], (), {}))
			self.__c = self.__c + 1
		if result == None and v[self.__c] != "N":
			raise ValueError("Unsupported value: " + v[self.__c])
		return result
		
	def __init__(self, UTF8 = False):
		self.UTF8 = UTF8
		
	def __serializeClass(self, v):
		i = 0
		s = ""
		tmp = []
		for key in v.__dict__:
			s = self.serialize(key)
			if s[0] == "i" or s[0] == "s":
				tmp.append(s)
				tmp.append(self.serialize(v.__dict__[key]))
				i = i + 1
		return [i, "".join(tmp)]
		
	def __slen(self, s):
		charcode = 0
		result = 0
		slen = len(s)
		if self.UTF8:
			while slen:
				slen = slen - 1
				try:
					charcode = ord(s[slen])
				except:
					charcode = 65536
				if charcode < 128:
					result = result + 1
				elif charcode < 2048:
					result = result + 2
				elif charcode < 65536:
					result = result + 3
				else:
					result = result + 4
		else:
			result = slen
		return result
		
	def __unserializeClass(self, v, C):
		tmp = None
		i = self.__c
		self.__c = v.find(":", i)
		i = int(v[i:self.__c])
		self.__c = self.__c + 2
		result = C()
		while i > 0:
			tmp = self.unserialize(v, False)
			result.__dict__[tmp] = self.unserialize(v, False)
			i = i - 1
		result.__dict__.update()
		return result