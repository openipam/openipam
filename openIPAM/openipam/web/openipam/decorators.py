

def login_not_required(func):
	func.login_not_required = True
	return func