#ifndef HOOK_REFLECT_H__
#define HOOK_REFLECT_H__

#include <cstddef>
#include <deque>
#include <list>
#include <map>
#include <set>
#include <span>
#include <type_traits>
#include <utility>
#include <vector>

#define reflect_field(x) v(#x, x);
#define reflect_const_field(x) v(#x, static_cast<const decltype(x)&>(x));
#define reflect_named(name, x) v(name, x);
#define reflect_const(name, x) v(name, static_cast<const decltype(x)&>(x));

#define REFLECT_ALL_1(v, a1) reflect_field(a1)
#define REFLECT_ALL_2(v, a1, a2) reflect_field(a1) reflect_field(a2)
#define REFLECT_ALL_3(v, a1, a2, a3) reflect_field(a1) reflect_field(a2) reflect_field(a3)
#define REFLECT_ALL_4(v, a1, a2, a3, a4) reflect_field(a1) reflect_field(a2) reflect_field(a3) reflect_field(a4)
#define REFLECT_ALL_5(v, a1, a2, a3, a4, a5) reflect_field(a1) reflect_field(a2) reflect_field(a3) reflect_field(a4) reflect_field(a5)
#define REFLECT_ALL_6(v, a1, a2, a3, a4, a5, a6) reflect_field(a1) reflect_field(a2) reflect_field(a3) reflect_field(a4) reflect_field(a5) reflect_field(a6)
#define REFLECT_ALL_7(v, a1, a2, a3, a4, a5, a6, a7) reflect_field(a1) reflect_field(a2) reflect_field(a3) reflect_field(a4) reflect_field(a5) reflect_field(a6) reflect_field(a7)
#define REFLECT_ALL_8(v, a1, a2, a3, a4, a5, a6, a7, a8) reflect_field(a1) reflect_field(a2) reflect_field(a3) reflect_field(a4) reflect_field(a5) reflect_field(a6) reflect_field(a7) reflect_field(a8)
#define REFLECT_ALL_9(v, a1, a2, a3, a4, a5, a6, a7, a8, a9) reflect_field(a1) reflect_field(a2) reflect_field(a3) reflect_field(a4) reflect_field(a5) reflect_field(a6) reflect_field(a7) reflect_field(a8) reflect_field(a9)
#define REFLECT_ALL_10(v, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10) reflect_field(a1) reflect_field(a2) reflect_field(a3) reflect_field(a4) reflect_field(a5) reflect_field(a6) reflect_field(a7) reflect_field(a8) reflect_field(a9) reflect_field(a10)
#define REFLECT_ALL_11(v, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11) reflect_field(a1) reflect_field(a2) reflect_field(a3) reflect_field(a4) reflect_field(a5) reflect_field(a6) reflect_field(a7) reflect_field(a8) reflect_field(a9) reflect_field(a10) reflect_field(a11)
#define REFLECT_ALL_12(v, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12) reflect_field(a1) reflect_field(a2) reflect_field(a3) reflect_field(a4) reflect_field(a5) reflect_field(a6) reflect_field(a7) reflect_field(a8) reflect_field(a9) reflect_field(a10) reflect_field(a11) reflect_field(a12)
#define REFLECT_ALL_GET(_1,_2,_3,_4,_5,_6,_7,_8,_9,_10,_11,_12,NAME,...) NAME
#define reflect_all(...) REFLECT_ALL_GET(__VA_ARGS__, REFLECT_ALL_12, REFLECT_ALL_11, REFLECT_ALL_10, REFLECT_ALL_9, REFLECT_ALL_8, REFLECT_ALL_7, REFLECT_ALL_6, REFLECT_ALL_5, REFLECT_ALL_4, REFLECT_ALL_3, REFLECT_ALL_2, REFLECT_ALL_1)(v, __VA_ARGS__)

template<typename T, typename = void>
struct has_reflect : std::false_type {};

template<typename...>
struct dependent_false : std::false_type {};

template<typename T, typename = void>
struct is_complete : std::false_type {};

template<typename T>
struct is_complete<T, std::void_t<decltype(sizeof(T))>> : std::true_type {};

template<typename T, bool = is_complete<T>::value>
struct is_blob_aggregate_impl : std::false_type {};

template<typename T>
struct is_blob_aggregate_impl<T, true>
    : std::bool_constant<!std::is_array_v<T> && std::is_aggregate_v<T> && std::is_trivially_copyable_v<T>> {};

template<typename T>
struct is_blob_aggregate : is_blob_aggregate_impl<T> {};

template<typename T, typename = void>
struct has_member_reflect : std::false_type {};

template<typename T>
struct has_member_reflect<T, std::void_t<decltype(std::declval<T&>().reflect(std::declval<int&>()))>> : std::true_type {};

template<typename T, typename = void>
struct reflect_adapter;

template<typename T, typename = void>
struct has_reflect_adapter : std::false_type {};

template<typename T>
struct has_reflect_adapter<T, std::void_t<decltype(reflect_adapter<T>::apply(std::declval<T&>(), std::declval<int&>()))>>
    : std::true_type {};

template<typename T>
struct has_reflect<T, std::enable_if_t<
    has_member_reflect<T>::value || has_reflect_adapter<T>::value
>> : std::true_type {};

template<typename T, typename Visitor>
void invoke_reflect(T& value, Visitor& v) {
    using Raw = std::remove_cv_t<std::remove_reference_t<T>>;
    if constexpr (has_member_reflect<Raw>::value) {
        value.reflect(v);
    } else {
        reflect_adapter<Raw>::apply(value, v);
    }
}

// const 重载：仅供 serialize_value 中的只读 SerializeVisitor 使用。
// 由于 visitor 不会修改字段，const_cast 在此场景下是安全的。
// 写回路径（set_param / SetFieldVisitor）始终通过上方的非 const 重载进入，不会触发 UB。
template<typename T, typename Visitor>
void invoke_reflect(const T& value, Visitor& v) {
    using Raw = std::remove_cv_t<std::remove_reference_t<T>>;
    invoke_reflect(const_cast<Raw&>(value), v);
}
template<typename T, typename = void>
struct is_smart_pointer : std::false_type {};

template<typename T>
struct is_smart_pointer<T, std::void_t<typename T::element_type,
    decltype(std::declval<T>().get())>> : std::true_type {};

template<typename T>
struct is_vector : std::false_type {};

template<typename T, typename A>
struct is_vector<std::vector<T, A>> : std::true_type {};

template<typename T>
struct is_deque : std::false_type {};

template<typename T, typename A>
struct is_deque<std::deque<T, A>> : std::true_type {};

template<typename T>
struct is_list : std::false_type {};

template<typename T, typename A>
struct is_list<std::list<T, A>> : std::true_type {};

template<typename T>
struct is_set : std::false_type {};

template<typename K, typename C, typename A>
struct is_set<std::set<K, C, A>> : std::true_type {};

template<typename T>
struct is_map : std::false_type {};

template<typename K, typename V, typename C, typename A>
struct is_map<std::map<K, V, C, A>> : std::true_type {};


template<typename T>
struct is_span : std::false_type {};

template<typename T, std::size_t E>
struct is_span<std::span<T, E>> : std::true_type {};

template<typename T>
struct is_byte_span : std::false_type {};

template<typename T, std::size_t E>
struct is_byte_span<std::span<T, E>>
    : std::bool_constant<std::is_same_v<std::remove_cv_t<T>, std::byte>> {};

#endif
