

#include "postgres.h"
#include "fmgr.h"

#include "utils/inet.h"

#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif

Datum macaddr_add( PG_FUNCTION_ARGS );
PG_FUNCTION_INFO_V1( macaddr_add );

int64 internal_macaddr_toint64( macaddr *mac );
macaddr* internal_int64_tomacaddr( int64 mac );

Datum
macaddr_add( PG_FUNCTION_ARGS )
{
	macaddr *addr = PG_GETARG_MACADDR_P(0);
	int64 addend = PG_GETARG_INT64(1);
	int64 sum;

	sum = addend + internal_macaddr_toint64(addr);

	if( sum >> (8*6) )
	{
		/* You added/subtracted too much */
		if( sum < 0 )
			ereport(ERROR,
					(errcode(ERRCODE_NUMERIC_VALUE_OUT_OF_RANGE),
					 errmsg("underflow in result")));
		else
			ereport(ERROR,
					(errcode(ERRCODE_NUMERIC_VALUE_OUT_OF_RANGE),
					 errmsg("overflow in result")));
	}

	PG_RETURN_MACADDR_P( internal_int64_tomacaddr(sum) );
}

int64 internal_macaddr_toint64( macaddr *mac )
{
	int64 result;
	result = ((int64)mac -> a << (8*5)) | ((int64)mac -> b << (8*4)) |
	       	((uint32_t)mac -> c << (8*3)) | ((uint32_t)mac -> d << (8*2)) |
	       	(mac -> e << (8*1)) | (mac -> f) ;
	return result;
}

macaddr* internal_int64_tomacaddr( int64 mac )
{
	macaddr *result;
	result = (macaddr *) palloc0(sizeof(macaddr));

	if( mac >> (8*6) )
		/* FIXME: out of range */
		ereport(ERROR,
				(errcode(ERRCODE_NUMERIC_VALUE_OUT_OF_RANGE),
				 errmsg("input is out of range")));
	
	result->a = (mac >> (8*5)) & 0xff;
	result->b = (mac >> (8*4)) & 0xff;
	result->c = (mac >> (8*3)) & 0xff;
	result->d = (mac >> (8*2)) & 0xff;
	result->e = (mac >> (8*1)) & 0xff;
	result->f = (mac) & 0xff;

	return result;
}

