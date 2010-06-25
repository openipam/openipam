
DROP OPERATOR + ( macaddr, bigint );

DROP CAST (macaddr AS bigint);

DROP CAST (bigint AS macaddr);


DROP FUNCTION macaddr_add (macaddr, bigint);

DROP FUNCTION macaddr_toint64 (macaddr);

DROP FUNCTION int64_tomacaddr (bigint);

