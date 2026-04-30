/*
 * Small C bridge into LuaJIT internals for Glimmer bytecode tools.
 * Must match the pinned LuaJIT in vendor/LuaJIT (GC layout, BC encoding).
 */
#include "lua.h"
#include "lauxlib.h"
#include "lj_obj.h"
#include "lj_bc.h"

const GCproto *glimmer_closure_proto(const void *closure)
{
	const GCfunc *fn = (const GCfunc *)closure;
	if (!fn || !isluafunc(fn))
		return NULL;
	return funcproto((GCfunc *)fn);
}

int glimmer_is_lua_closure(const void *closure)
{
	const GCfunc *fn = (const GCfunc *)closure;
	return fn && isluafunc(fn) ? 1 : 0;
}

uint32_t glimmer_proto_sizebc(const GCproto *pt)
{
	return pt->sizebc;
}

uint32_t glimmer_proto_sizekgc(const GCproto *pt)
{
	return pt->sizekgc;
}

const BCIns *glimmer_proto_bc(const GCproto *pt)
{
	return (const BCIns *)((const char *)pt + sizeof(GCproto));
}

uint32_t glimmer_proto_firstline(const GCproto *pt)
{
	return (uint32_t)pt->firstline;
}

uint32_t glimmer_proto_numline(const GCproto *pt)
{
	return (uint32_t)pt->numline;
}

const GCproto *glimmer_proto_kgc_proto_at(const GCproto *pt, ptrdiff_t kidx)
{
	GCproto *ptm = (GCproto *)pt;
	if (kidx >= 0 || kidx < -(ptrdiff_t)ptm->sizekgc)
		return NULL;
	{
		GCobj *gc = gcref(mref(ptm->k, GCRef)[kidx]);
		if (!gc)
			return NULL;
		if (gc->gch.gct != ~LJ_TPROTO)
			return NULL;
		return &gc->pt;
	}
}

const GCproto *glimmer_proto_from_bc_kgc_d(const GCproto *pt, uint32_t ins)
{
	ptrdiff_t kidx = ~(ptrdiff_t)bc_d((BCIns)ins);
	return glimmer_proto_kgc_proto_at(pt, kidx);
}

ptrdiff_t glimmer_kgc_index_from_bc_d(uint32_t ins)
{
	return ~(ptrdiff_t)bc_d((BCIns)ins);
}

uint16_t glimmer_proto_uv_desc(const GCproto *pt, uint32_t uvidx)
{
	GCproto *ptm = (GCproto *)pt;
	if (uvidx >= ptm->sizeuv)
		return (uint16_t)0xffff;
	return mref(ptm->uv, uint16_t)[uvidx];
}
