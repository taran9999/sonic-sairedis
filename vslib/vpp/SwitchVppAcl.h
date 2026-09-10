#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_ACL_ATTRS 12

/*
 * SAI HLD restricts SAI_ACL_ENTRY_ATTR_ACTION_MIRROR_{INGRESS,EGRESS} to a
 * single mirror session OID per rule. We pre-allocate a small backing buffer
 * (size > 1 to safely absorb a slightly larger src on re-fetch without
 * BUFFER_OVERFLOW dropping the attr in get_max).
 */
#define MAX_ACL_MIRROR_OIDS 4

/*
 * Maximum number of ingress port OIDs we re-fetch for a single ACL entry's
 * SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS qualifier.
 */
#define MAX_ACL_IN_PORTS 64

/*
 * A VPP ACL rule is scoped to one ingress interface and one IP family, so a
 * single SAI entry can expand into (ingress ports x families x L4 protocols)
 * rules. Past this many we log a warning: the expansion is legal but grows the
 * acl_add_replace message.
 */
#define ACL_MAX_RULES_PER_ACE 64

typedef struct _acl_tbl_entries_ {
    uint32_t priority;

    sai_attribute_t  attr_range;
    sai_object_id_t  range_objid_list[2];

    sai_u32_range_t range_limit[2];
    sai_acl_range_type_t range_type[2];
    uint32_t range_count;
    sai_attribute_t attrs[MAX_ACL_ATTRS];
    uint32_t attrs_count;

    /*
     * Backing storage for MIRROR_INGRESS / MIRROR_EGRESS object lists.
     * get_max() copies attribute values through transfer_list(), which leaves
     * dst.list = NULL when dst.count was 0 on entry (calloc'd struct). We
     * use these slots to re-fetch the OID list with a properly sized buffer.
     */
    sai_object_id_t mirror_ingress_objid_list[MAX_ACL_MIRROR_OIDS];
    sai_object_id_t mirror_egress_objid_list[MAX_ACL_MIRROR_OIDS];

    /*
     * Backing storage for the SAI_ACL_ENTRY_ATTR_FIELD_IN_PORTS object list.
     * Same transfer_list() NULL-list caveat as the mirror lists above: get_max()
     * leaves dst.list = NULL, so we re-fetch the port OID list into this buffer.
     */
    sai_object_id_t in_ports_objid_list[MAX_ACL_IN_PORTS];
} acl_tbl_entries_t;

typedef struct ordered_ace_list_ {
    uint32_t index;
    uint32_t priority;
    sai_object_id_t ace_oid;
    bool is_tunterm;
    // each ACE in SONiC maps to one or more VPP consequential ACL rules
    // vpp_rule_base_index is the starting index of these rules in VPP ACL
    uint32_t vpp_rule_base_index;
    // number of VPP ACL rules created for this ACE
    uint32_t num_rules;
} ordered_ace_list_t;

#ifdef __cplusplus
}
#endif

