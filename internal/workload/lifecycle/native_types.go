// SPDX-License-Identifier: Apache-2.0

package lifecycle

import (
	"go/constant"
	"go/token"
	"go/types"
	"path"
	"reflect"
	"slices"

	"github.com/traefik/yaegi/stdlib"
)

// nativeTypeImporter adapts the exact compiled-in interpreter exports to Go's
// type checker. It never calls reflected functions, exports a host handle,
// executes initialization or reads installed Go sources/module caches.
type nativeTypeImporter struct {
	packages  map[string]*types.Package
	converted map[reflect.Type]types.Type
	count     int
}

func newNativeTypeImporter() *nativeTypeImporter {
	return &nativeTypeImporter{packages: map[string]*types.Package{}, converted: map[reflect.Type]types.Type{}}
}
func (i *nativeTypeImporter) pkg(name string) *types.Package {
	if p := i.packages[name]; p != nil {
		return p
	}
	p := types.NewPackage(name, path.Base(name))
	if name == checkerSDK {
		p = types.NewPackage(name, "lifecycle")
	}
	i.packages[name] = p
	return p
}
func (i *nativeTypeImporter) Import(name string) (*types.Package, error) {
	if name != checkerSDK && !supportedStandardPackage(name) {
		return nil, ErrSource
	}
	p := i.pkg(name)
	if p.Complete() {
		return p, nil
	}
	exports := stdlib.Symbols[name+"/"+path.Base(name)]
	if name == checkerSDK {
		exports = sdkSymbols()[checkerSDK+"/lifecycle"]
	}
	if len(exports) == 0 {
		return nil, ErrSource
	}
	names := make([]string, 0, len(exports))
	for name := range exports {
		if token.IsExported(name) {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	for _, name := range names {
		value := exports[name]
		if !value.IsValid() {
			continue
		}
		var object types.Object
		if literal, ok := value.Interface().(constant.Value); ok {
			kind := types.UntypedInt
			switch literal.Kind() {
			case constant.Bool:
				kind = types.UntypedBool
			case constant.String:
				kind = types.UntypedString
			case constant.Float:
				kind = types.UntypedFloat
			case constant.Complex:
				kind = types.UntypedComplex
			}
			object = types.NewConst(token.NoPos, p, name, types.Typ[kind], literal)
		} else if value.Kind() == reflect.Pointer && value.IsNil() && !value.CanAddr() {
			object = types.NewTypeName(token.NoPos, p, name, i.convert(value.Type().Elem()))
		} else if value.Kind() == reflect.Func {
			signature := i.convert(value.Type()).(*types.Signature)
			object = types.NewFunc(token.NoPos, p, name, signature)
		} else {
			typ := i.convert(value.Type())
			if literal := nativeConstant(value); literal != nil && !value.CanAddr() {
				object = types.NewConst(token.NoPos, p, name, typ, literal)
			} else {
				object = types.NewVar(token.NoPos, p, name, typ)
			}
		}
		if p.Scope().Lookup(name) == nil {
			p.Scope().Insert(object)
		}
	}
	p.MarkComplete()
	return p, nil
}
func nativeConstant(v reflect.Value) constant.Value {
	switch v.Kind() {
	case reflect.Bool:
		return constant.MakeBool(v.Bool())
	case reflect.String:
		return constant.MakeString(v.String())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return constant.MakeInt64(v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		return constant.MakeUint64(v.Uint())
	case reflect.Float32, reflect.Float64:
		return constant.MakeFloat64(v.Float())
	case reflect.Complex64, reflect.Complex128:
		n := v.Complex()
		return constant.BinaryOp(constant.MakeFloat64(real(n)), token.ADD, constant.MakeImag(constant.MakeFloat64(imag(n))))
	}
	return nil
}
func (i *nativeTypeImporter) convert(t reflect.Type) types.Type {
	if result := i.converted[t]; result != nil {
		return result
	}
	if t == reflect.TypeOf((*error)(nil)).Elem() {
		return types.Universe.Lookup("error").Type()
	}
	i.count++
	if i.count > 16384 {
		panic("native type metadata limit")
	}
	if t.Name() != "" && t.PkgPath() != "" {
		p := i.pkg(t.PkgPath())
		named := types.NewNamed(types.NewTypeName(token.NoPos, p, t.Name(), nil), nil, nil)
		i.converted[t] = named
		named.SetUnderlying(i.underlying(t))
		if t.Kind() != reflect.Interface {
			seen := map[string]bool{}
			for _, receiver := range []reflect.Type{t, reflect.PointerTo(t)} {
				for index := 0; index < receiver.NumMethod(); index++ {
					method := receiver.Method(index)
					if seen[method.Name] {
						continue
					}
					seen[method.Name] = true
					rt := types.Type(named)
					if receiver.Kind() == reflect.Pointer {
						rt = types.NewPointer(named)
					}
					signature := i.signature(method.Type, 1, types.NewVar(token.NoPos, p, "", rt))
					named.AddMethod(types.NewFunc(token.NoPos, p, method.Name, signature))
				}
			}
		}
		return named
	}
	result := i.underlying(t)
	i.converted[t] = result
	return result
}
func (i *nativeTypeImporter) signature(t reflect.Type, skip int, receiver *types.Var) *types.Signature {
	args := make([]*types.Var, 0, t.NumIn()-skip)
	for n := skip; n < t.NumIn(); n++ {
		args = append(args, types.NewVar(token.NoPos, nil, "", i.convert(t.In(n))))
	}
	results := make([]*types.Var, 0, t.NumOut())
	for n := 0; n < t.NumOut(); n++ {
		results = append(results, types.NewVar(token.NoPos, nil, "", i.convert(t.Out(n))))
	}
	return types.NewSignatureType(receiver, nil, nil, types.NewTuple(args...), types.NewTuple(results...), t.IsVariadic())
}
func (i *nativeTypeImporter) underlying(t reflect.Type) types.Type {
	switch t.Kind() {
	case reflect.Bool:
		return types.Typ[types.Bool]
	case reflect.Int:
		return types.Typ[types.Int]
	case reflect.Int8:
		return types.Typ[types.Int8]
	case reflect.Int16:
		return types.Typ[types.Int16]
	case reflect.Int32:
		return types.Typ[types.Int32]
	case reflect.Int64:
		return types.Typ[types.Int64]
	case reflect.Uint:
		return types.Typ[types.Uint]
	case reflect.Uint8:
		return types.Typ[types.Uint8]
	case reflect.Uint16:
		return types.Typ[types.Uint16]
	case reflect.Uint32:
		return types.Typ[types.Uint32]
	case reflect.Uint64:
		return types.Typ[types.Uint64]
	case reflect.Uintptr:
		return types.Typ[types.Uintptr]
	case reflect.Float32:
		return types.Typ[types.Float32]
	case reflect.Float64:
		return types.Typ[types.Float64]
	case reflect.Complex64:
		return types.Typ[types.Complex64]
	case reflect.Complex128:
		return types.Typ[types.Complex128]
	case reflect.String:
		return types.Typ[types.String]
	case reflect.Pointer:
		return types.NewPointer(i.convert(t.Elem()))
	case reflect.Slice:
		return types.NewSlice(i.convert(t.Elem()))
	case reflect.Array:
		return types.NewArray(i.convert(t.Elem()), int64(t.Len()))
	case reflect.Map:
		return types.NewMap(i.convert(t.Key()), i.convert(t.Elem()))
	case reflect.Chan:
		direction := types.SendRecv
		if t.ChanDir() == reflect.SendDir {
			direction = types.SendOnly
		} else if t.ChanDir() == reflect.RecvDir {
			direction = types.RecvOnly
		}
		return types.NewChan(direction, i.convert(t.Elem()))
	case reflect.Func:
		return i.signature(t, 0, nil)
	case reflect.Interface:
		methods := make([]*types.Func, 0, t.NumMethod())
		for n := 0; n < t.NumMethod(); n++ {
			m := t.Method(n)
			var p *types.Package
			if m.PkgPath != "" {
				p = i.pkg(m.PkgPath)
			}
			methods = append(methods, types.NewFunc(token.NoPos, p, m.Name, i.signature(m.Type, 0, nil)))
		}
		return types.NewInterfaceType(methods, nil).Complete()
	case reflect.Struct:
		fields := make([]*types.Var, 0, t.NumField())
		tags := make([]string, 0, t.NumField())
		for n := 0; n < t.NumField(); n++ {
			f := t.Field(n)
			var p *types.Package
			if f.PkgPath != "" {
				p = i.pkg(f.PkgPath)
			}
			name := f.Name
			fields = append(fields, types.NewField(token.NoPos, p, name, i.convert(f.Type), f.Anonymous))
			tags = append(tags, string(f.Tag))
		}
		return types.NewStruct(fields, tags)
	case reflect.UnsafePointer:
		return types.Typ[types.UnsafePointer]
	}
	panic("unsupported native type metadata")
}
