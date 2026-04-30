/*
 * Small C bridge into LuaJIT internals for Glimmer bytecode tools.
 * Must match the pinned LuaJIT in vendor/LuaJIT (GC layout, BC encoding).
 */
#include <stdlib.h>
#include <string.h>
#include "lua.h"
#include "lauxlib.h"
#include "lj_obj.h"
#include "lj_bc.h"
#include "lj_debug.h"
#include "lj_bcdump.h"

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

uint8_t glimmer_proto_numparams(const GCproto *pt)
{
	return pt ? pt->numparams : (uint8_t)0;
}

uint8_t glimmer_proto_framesize(const GCproto *pt)
{
	return pt ? pt->framesize : (uint8_t)0;
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

/* Bytecode index `bc_idx` is 0 .. sizebc-1 (same as Glimmer's per-insn PC). */
int32_t glimmer_proto_line_at_bc(const GCproto *pt, uint32_t bc_idx)
{
	if (!pt || bc_idx >= pt->sizebc)
		return -1;
	return (int32_t)lj_debug_line((GCproto *)pt, (BCPos)bc_idx);
}

int glimmer_proto_has_lineinfo(const GCproto *pt)
{
	return (pt && proto_lineinfo(pt) != NULL) ? 1 : 0;
}

const char *glimmer_proto_chunkname_cstr(const GCproto *pt)
{
	if (!pt)
		return "";
	return proto_chunknamestr(pt);
}

typedef struct {
	unsigned char *ptr;
	size_t len;
	size_t cap;
} GlimmerDumpBuf;

static int glimmer_dump_writer(lua_State *L, const void *p, size_t sz, void *ud)
{
	GlimmerDumpBuf *b = (GlimmerDumpBuf *)ud;
	size_t need;
	(void)L;

	if (sz == 0)
		return 0;
	need = b->len + sz;
	if (need < b->len)
		return 1;
	if (need > b->cap) {
		size_t ncap = b->cap ? b->cap : 256;
		while (ncap < need) {
			if (ncap > ((size_t)1 << (sizeof(size_t) * 8 - 2)))
				return 1;
			ncap *= 2;
		}
		{
			unsigned char *n = (unsigned char *)realloc(b->ptr, ncap);
			if (!n)
				return 1;
			b->ptr = n;
			b->cap = ncap;
		}
	}
	memcpy(b->ptr + b->len, p, sz);
	b->len += sz;
	return 0;
}

/*
 * Dump the Lua closure on the stack top to LuaJIT bytecode (same format as string.dump).
 * When strip_debug is non-zero, omits line/debug info from the blob (use external maps).
 * Returns: 0 = ok, 2 = stack empty, 3 = not a Lua function, 4 = lj_bcwrite failed.
 * On success, *out_bytes must be released with glimmer_dump_bytes_free.
 */
int glimmer_dump_stack_function(void *L_void, int strip_debug,
				unsigned char **out_bytes, size_t *out_len)
{
	lua_State *L = (lua_State *)L_void;
	GlimmerDumpBuf buf = { NULL, 0, 0 };
	cTValue *o;
	uint32_t flags = 0;

	if (strip_debug)
		flags |= BCDUMP_F_STRIP;

	if (L->top <= L->base)
		return 2;
	o = L->top - 1;
	if (!tvisfunc(o) || !isluafunc(funcV(o)))
		return 3;

	if (lj_bcwrite(L, funcproto(funcV(o)), glimmer_dump_writer, &buf, flags)) {
		free(buf.ptr);
		return 4;
	}

	*out_bytes = buf.ptr;
	*out_len = buf.len;
	return 0;
}

void glimmer_dump_bytes_free(unsigned char *p)
{
	free(p);
}

/*
 * KGC string constant at negative index kidx (-1 .. -sizekgc).
 * Returns 1 if slot holds a string; writes pointer + length (not NUL-terminated).
 */
int glimmer_proto_kgc_str(const GCproto *pt, ptrdiff_t kidx, const char **data,
			  size_t *len)
{
	GCproto *ptm = (GCproto *)pt;
	GCobj *o;

	if (!ptm || kidx >= 0 || kidx < -(ptrdiff_t)ptm->sizekgc)
		return 0;
	o = gcref(mref(ptm->k, GCRef)[kidx]);
	if (!o || o->gch.gct != ~LJ_TSTR)
		return 0;
	{
		GCstr *str = gco2str(o);
		*data = strdata(str);
		*len = str->len;
	}
	return 1;
}

/*
 * Number constant pool entry idx in 0 .. sizekn-1.
 * Returns 1 if integer, 2 if double, 0 on failure / unsupported tag.
 */
int glimmer_proto_knum_kind(const GCproto *pt, uint32_t idx, int32_t *ival,
			     double *fval)
{
	GCproto *ptm = (GCproto *)pt;
	const TValue *tv;

	if (!ptm || idx >= ptm->sizekn)
		return 0;
	tv = proto_knumtv(ptm, idx);
#if LJ_DUALNUM
	if (tvisint(tv)) {
		*ival = intV(tv);
		return 1;
	}
#endif
	if (tvisnum(tv)) {
		*fval = numV(tv);
		return 2;
	}
	return 0;
}
