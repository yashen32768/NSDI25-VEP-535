/*@ Extern Coq (store_char_array : Z -> Z -> list Z -> Assertion)
               (store_char_array_missing_i_rec: Z -> Z -> Z -> Z -> list Z -> Assertion)
               (store_uchar_array : Z -> Z -> list Z -> Assertion)
               (store_uchar_array_missing_i_rec: Z -> Z -> Z -> Z -> list Z -> Assertion)
               (store_int_array : Z -> Z -> list Z -> Assertion)
               (store_int_array_missing_i_rec: Z -> Z -> Z -> Z -> list Z -> Assertion)
               (store_uint_array : Z -> Z -> list Z -> Assertion)
               (store_uint_array_missing_i_rec: Z -> Z -> Z -> Z -> list Z -> Assertion)
               (Znth: {A} -> Z -> list A -> A -> A)
               (replace_Znth: {A} -> Z -> A -> list A -> list A)
*/

/*@ include strategies "char_array.strategies" */
/*@ include strategies "uchar_array.strategies" */
/*@ include strategies "int_array.strategies" */
/*@ include strategies "uint_array.strategies"*/
