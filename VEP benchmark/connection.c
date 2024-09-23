#include "bpf.h"

struct connection{
    char key[128];
    unsigned int num_packet;
    unsigned int mark;
    //pthread_mutex_t mutex_num_packet;
    //pthread_mutex_t mutex_buffer;
    //char  buffer[8*1500];
    unsigned int lengthsofar;
    struct connection * next; 
};

struct identifier{
    int mark;//this is the mark as ti appears in the config file 
             // before it goes to netfilter , it will get modified by mask
    char  name[32];
    char  pattern[512];
//    int eflags;  //for regexec
 //   int cflags;  //for regcomp
  //  regex_t preg; // the compiled regex
};

struct conntrack{
    int queuenum;
    int iden_num;
    struct identifier *iden_array;
    struct connection *conn_list;
};

/*@ Extern Coq (ConnListrep : Z -> Assertion)
               (ConnListseg : Z -> Z -> Assertion)
*/

/*@ include strategies "Conn.strategies" */

static inline int strcmp (char *p1, char *p2) 
/*@ With n0 m0 l0 n1 m1 l1 
    Require 0 <= n0 && l0[n0] == 0 && n0 < m0 && 0 <= n1 && l1[n1] == 0 && n1 < m1 && store_char_array(p1, m0, l0) * store_char_array(p2, m1, l1)
    Ensure exists v, __return == v && store_char_array(p2, m1, l1) * store_char_array(p1, m0, l0)
*/
{
    //#pragma unroll
    unsigned int i;
    /*@ Inv 
        0 <= i && i <= n0 && i <= n1 */
    for (i = 0;  ; i++) {
        char c1 = p1[i];
        char c2 = p2[i];
        if (c2 == (char)0) break;
        if (c1 != c2) return 0;
        if (c1 == (char)0)
            break;
    }
    return 1;
}

struct connection * get_connection(struct conntrack * connt, char * key)
/*@ With n0 m0 l0 Connlist
    Require 0 <= n0 && l0[n0] == 0 && n0 < m0 && connt -> conn_list == Connlist && store_char_array(key, m0, l0) * ConnListrep(Connlist)
    Ensure exists v, __return == v && TT
*/
{
    struct connection * p ;
    if(connt == (struct conntrack *)0 || key == (char *)0) return (struct connection *)0;
    p = connt->conn_list;
    /*@ Inv 
        ConnListrep(p) * ConnListseg(Connlist, p)
    */
    while(p != (struct connection *)0){
        char * p_key = (char *)&p->key;
        if(strcmp(p_key , key) == 0) 
            break;
        p = p->next; 
    }
    if(p == (struct connection *)0) 
        return (struct connection *)0;
    else     
        return p;
}