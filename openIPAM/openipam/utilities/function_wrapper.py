class fcn_wrapper:
    def __getattribute__(self, name):
        # print '?%s' % repr(name)
        if (
            name in ["__getattribute__", "__call__", "__init__"]
            or name[:11] == "fcn_wrapper"
        ):
            try:
                obj = object.__getattribute__(self, name)
                # print 'fcn_wrapper: getattr(%s) -> %s' % (repr(name), repr(obj),)
                return obj
            except Exception:
                # print 'meh'
                # print e
                raise
        try:
            fcn = object.__getattribute__(self, "fcn_wrapper_fcn")
        except Exception as e:
            print(e)
            raise
            # print '--------'
        obj = getattr(fcn, name)
        # print repr(obj)
        # print '--------'
        return obj

    def __call__(self, *args, **kw):
        name = self.fcn_wrapper_name
        # print '********->%s' % name
        for k in self.fcn_wrapper_kwargs:
            if k in kw:
                raise Exception(
                    "Bad programmer.  No donut.  %s was given twice (%s, %s)."
                    % (k, kw[k], self.fcn_wrapper_kwargs[k])
                )
            kw[k] = self.fcn_wrapper_kwargs[k]
        if hasattr(self.fcn_wrapper_obj, "log_call"):
            self.fcn_wrapper_obj.log_call(name, *args, **kw)
        return self.fcn_wrapper_fcn(*args, **kw)

    def __init__(self, obj, fcn, name, kwargs=None):
        if not kwargs:
            kwargs = {}
        self.fcn_wrapper_fcn = fcn
        self.fcn_wrapper_obj = obj
        self.fcn_wrapper_name = name
        self.fcn_wrapper_kwargs = kwargs
        # print '+%(name)s() fcn: %(fcn)s obj: %(obj)s' % locals()
        # print self.fcn_wrapper_name
        # print self.fcn_wrapper_name
