
CREATE OR REPLACE FUNCTION macaddr_add (macaddr, bigint)
	RETURNS macaddr
	AS '$libdir/macaddr_contrib', 'macaddr_add'
	LANGUAGE C
	STRICT IMMUTABLE;

CREATE OPERATOR + (
	    leftarg = macaddr,
	    rightarg = bigint,
	    procedure = macaddr_add,
	    commutator = +
);

