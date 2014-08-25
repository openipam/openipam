
CREATE OR REPLACE FUNCTION macaddr_add (macaddr, bigint)
	RETURNS macaddr
	AS '$libdir/macaddr_contrib', 'macaddr_add'
	LANGUAGE C
	STRICT IMMUTABLE;

CREATE OR REPLACE FUNCTION macaddr_toint64 (macaddr)
	RETURNS bigint
	AS '$libdir/macaddr_contrib', 'macaddr_toint64'
	LANGUAGE C
	STRICT IMMUTABLE;

CREATE OR REPLACE FUNCTION int64_tomacaddr (bigint)
	RETURNS macaddr
	AS '$libdir/macaddr_contrib', 'int64_tomacaddr'
	LANGUAGE C
	STRICT IMMUTABLE;

CREATE OPERATOR + (
	    leftarg = macaddr,
	    rightarg = bigint,
	    procedure = macaddr_add,
	    commutator = +
);

CREATE CAST (macaddr AS bigint)
	WITH FUNCTION macaddr_toint64 (macaddr);

CREATE CAST (bigint AS macaddr)
	WITH FUNCTION int64_tomacaddr (bigint);


