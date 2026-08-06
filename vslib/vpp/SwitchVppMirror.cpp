#include "SwitchVpp.h"
#include "SwitchVppUtils.h"

#include "meta/sai_serialize.h"
#include "swss/logger.h"
#include "vppxlate/SaiVppXlate.h"

#include <cstdlib>
#include <cstring>

using namespace saivs;

sai_status_t SwitchVpp::createMirrorSession(
        _In_ sai_object_id_t object_id,
        _In_ sai_object_id_t switch_id,
        _In_ uint32_t attr_count,
        _In_ const sai_attribute_t *attr_list)
{
    SWSS_LOG_ENTER();

    const sai_attribute_value_t *value;
    uint32_t attr_index;
    MirrorSessionInfo info{};

    auto sid = sai_serialize_object_id(object_id);

    CHECK_STATUS(find_attrib_in_list(attr_count, attr_list, SAI_MIRROR_SESSION_ATTR_TYPE, &value, &attr_index));
    int32_t mirror_type = value->s32;

    if(mirror_type == SAI_MIRROR_SESSION_TYPE_LOCAL) {
        CHECK_STATUS(find_attrib_in_list(attr_count, attr_list, SAI_MIRROR_SESSION_ATTR_MONITOR_PORT, &value, &attr_index));
        sai_object_id_t monitor_port = value->oid;

        std::string hwif_name;
        if(!vpp_get_hwif_name(monitor_port, 0, hwif_name)) {
            SWSS_LOG_ERROR("Failed to get hwif name for monitor port %s", sai_serialize_object_id(monitor_port).c_str());
            return SAI_STATUS_FAILURE;
        }

        int sw_idx = get_sw_if_idx(hwif_name.c_str());
        if(sw_idx < 0) {
            SWSS_LOG_ERROR("Failed to get sw_if_index for hwif %s", hwif_name.c_str());
            return SAI_STATUS_FAILURE;
        }

        SWSS_LOG_INFO("SPAN mirror session info: monitor_port=%s, hwif_name=%s, sw_if_index=%d",
            sai_serialize_object_id(monitor_port).c_str(), hwif_name.c_str(), sw_idx);
        
        info.sw_if_index = (uint32_t)sw_idx;
        info.is_erspan = false;
    } else if(mirror_type == SAI_MIRROR_SESSION_TYPE_ENHANCED_REMOTE) {
        CHECK_STATUS(find_attrib_in_list(attr_count, attr_list, SAI_MIRROR_SESSION_ATTR_SRC_IP_ADDRESS, &value, &attr_index));
        sai_ip_address_t src_ip = value->ipaddr;

        CHECK_STATUS(find_attrib_in_list(attr_count, attr_list, SAI_MIRROR_SESSION_ATTR_DST_IP_ADDRESS, &value, &attr_index));
        sai_ip_address_t dst_ip = value->ipaddr;

        // GRE protocol/ethertype to emit in the encap header. Although SAI marks
        // this MANDATORY_ON_CREATE, orchagent may program it via a later SET, so
        // do NOT hard-fail session creation when it is absent: default to the
        // SONiC Everflow value (0x88BE) instead. Hard-failing here would leave
        // the mirror session non-existent and break every ACL rule that refers
        // to it.
        uint16_t gre_protocol = 0x88BE;
        if (find_attrib_in_list(attr_count, attr_list, SAI_MIRROR_SESSION_ATTR_GRE_PROTOCOL_TYPE, &value, &attr_index) == SAI_STATUS_SUCCESS) {
            gre_protocol = value->u16;
        }

        // Outer tunnel header TTL. Optional (SAI default 255).
        uint8_t session_ttl = 255;
        if (find_attrib_in_list(attr_count, attr_list, SAI_MIRROR_SESSION_ATTR_TTL, &value, &attr_index) == SAI_STATUS_SUCCESS) {
            session_ttl = value->u8;
        }

        int session_id = m_erspan_session_id_pool.alloc();
        if (session_id < 0) {
            SWSS_LOG_ERROR("ERSPAN session id pool exhausted (max 1024 in-flight sessions)");
            return SAI_STATUS_INSUFFICIENT_RESOURCES;
        }

        vpp_gre_tunnel_t tunnel{};
        sai_ip_address_t_to_vpp_ip_addr_t(src_ip, tunnel.src);
        sai_ip_address_t_to_vpp_ip_addr_t(dst_ip, tunnel.dst);
        // Use an ERSPAN (type 2) GRE tunnel: it is the only VPP GRE tunnel type
        // whose L2 clone/delivery path actually forwards the ACL-injected
        // mirror copy. SONiC "ERSPAN" is really plain GRE with a configured
        // protocol and NO GRE sequence number and NO ERSPAN type-II shim.
        // Setting tunnel.gre_protocol signals the (patched) VPP GRE plugin to
        // emit that protocol with flags=0 and to suppress the type-II shim,
        // while keeping the ERSPAN tunnel's working delivery path. VPP's stock
        // ERSPAN GRE protocol is already 0x88BE, matching SONiC Everflow.
        tunnel.type = 2;
        tunnel.session_id = (uint16_t)session_id;
        tunnel.gre_protocol = gre_protocol;
        // VPP forwards the GRE-encapped packet to the tunnel destination through
        // one more IP rewrite, which decrements the outer TTL once. Compensate
        // by adding one so the packet on the wire carries exactly the
        // session-configured TTL.
        if (session_ttl > 0 && session_ttl < 255) {
            tunnel.ttl = (uint8_t)(session_ttl + 1);
        } else {
            tunnel.ttl = session_ttl;
        }

        // The GRE tunnel instance drives the greN interface name and its entry
        // in VPP's interface-name hash. Do NOT derive it from session_id: the
        // pool recycles freed session ids (alloc() returns the lowest free
        // bit), so a remove+recreate would delete greN and immediately re-add
        // greN while the old teardown is still in flight, corrupting the VPP
        // heap. Use a strictly monotonic instance so a just-deleted interface
        // name is never reused.
        tunnel.instance = m_next_gre_instance++;
        tunnel.outer_table_id = 0;

        uint32_t gre_instance = tunnel.instance;
        uint32_t gre_sw_if_index = 0;
        SWSS_LOG_NOTICE("Creating GRE mirror tunnel: type=%u session_id=%d instance=%u gre_protocol=0x%04x ttl=%u(session_ttl=%u)",
            tunnel.type, session_id, tunnel.instance, gre_protocol, tunnel.ttl, session_ttl);
        int ret = vpp_gre_tunnel_add_del(&tunnel, true, &gre_sw_if_index);
        if(ret != 0) {
            SWSS_LOG_ERROR("Failed to add GRE tunnel for ERSPAN session, ret=%d", ret);
            m_erspan_session_id_pool.free((uint32_t)session_id);
            return SAI_STATUS_FAILURE;
        }
        SWSS_LOG_NOTICE("GRE mirror tunnel created: session_id=%d sw_if_index=%u", session_id, gre_sw_if_index);

        // Bring the GRE interface up using the sw_if_index returned by the tunnel
        // add above. Do NOT call refresh_interfaces_list() here: that performs a
        // full teardown and rebuild of VPP's global interface-name hashes, and
        // repeating it on every mirror create (each ECMP test re-points the
        // session via remove+create) churns the VPP clib heap until a hash-grow
        // realloc trips its free-list integrity check and aborts syncd. Setting
        // the state directly by index avoids the name lookup that needed it.
        std::string gre_ifname = "gre" + std::to_string(gre_instance);
        SWSS_LOG_INFO("gre tunnel created with ifname %s sw_if_index %u", gre_ifname.c_str(), gre_sw_if_index);
        int up_ret = interface_set_state_by_index(gre_sw_if_index, true);
        if(up_ret != 0) {
            SWSS_LOG_ERROR("Failed to bring up gre tunnel %s (sw_if_index %u), ret=%d", gre_ifname.c_str(), gre_sw_if_index, up_ret);
            vpp_gre_tunnel_add_del(&tunnel, false, &gre_sw_if_index);
            m_erspan_session_id_pool.free((uint32_t)session_id);
            return SAI_STATUS_FAILURE;
        }

        info.sw_if_index = gre_sw_if_index;
        info.is_erspan = true;
        info.src_ip = tunnel.src;
        info.dst_ip = tunnel.dst;
        info.session_id = (uint16_t)session_id;
        info.gre_instance = gre_instance;

        // Pin the ERSPAN encap to the single stable monitor port that
        // orchagent's MirrorOrch already resolved for us. MirrorOrch selects
        // ONE next hop for the mirror destination and passes its egress port
        // (SAI_MIRROR_SESSION_ATTR_MONITOR_PORT) and neighbor MAC
        // (SAI_MIRROR_SESSION_ATTR_DST_MAC_ADDRESS), re-pointing them via SET
        // only when that member leaves the ECMP group. Honor that here by
        // installing a /32 host route for dst_ip out the monitor port so the
        // encapped copy egresses one STABLE port, instead of letting VPP hash
        // the constant outer header over the mirror-dst ECMP load-balance
        // (which re-shuffles on every membership change). If the monitor port
        // or its nexthop is not resolvable, fall back to plain FIB forwarding.
        info.monitor_pinned = false;
        info.monitor_port = SAI_NULL_OBJECT_ID;
        const sai_attribute_value_t *mon_value;
        uint32_t mon_index;
        const sai_attribute_value_t *mac_value;
        uint32_t mac_index;
        if (find_attrib_in_list(attr_count, attr_list, SAI_MIRROR_SESSION_ATTR_MONITOR_PORT, &mon_value, &mon_index) == SAI_STATUS_SUCCESS
            && find_attrib_in_list(attr_count, attr_list, SAI_MIRROR_SESSION_ATTR_DST_MAC_ADDRESS, &mac_value, &mac_index) == SAI_STATUS_SUCCESS)
        {
            applyErspanMonitor(info, mon_value->oid, mac_value->mac);
        }
    } else {
        SWSS_LOG_ERROR("Unsupported mirror session type %d", mirror_type);
        return SAI_STATUS_FAILURE;
    }

    sai_status_t create_status = create_internal(SAI_OBJECT_TYPE_MIRROR_SESSION, sid, switch_id, attr_count, attr_list);
    if(create_status != SAI_STATUS_SUCCESS) {
        SWSS_LOG_ERROR("Failed to create mirror session %s in SAI DB, status=%d", sid.c_str(), create_status);
        // Unwind the VPP resources allocated above. The GRE tunnel-scoped locals
        // (tunnel/gre_sw_if_index/session_id) are out of scope here, so rebuild
        // the delete key from info exactly as removeMirrorSession does.
        if(info.is_erspan) {
            if(info.monitor_pinned) {
                pinErspanMonitor(info, false);
            }
            vpp_gre_tunnel_t tunnel{};
            tunnel.instance = info.gre_instance;
            tunnel.type = 2;
            tunnel.src = info.src_ip;
            tunnel.dst = info.dst_ip;
            tunnel.session_id = info.session_id;
            tunnel.outer_table_id = 0;
            uint32_t sw_if_index = 0;
            int ret = vpp_gre_tunnel_add_del(&tunnel, false, &sw_if_index);
            if(ret != 0) {
                SWSS_LOG_ERROR("Failed to remove GRE tunnel for ERSPAN session after SAI DB create failure, ret=%d", ret);
            }
            m_erspan_session_id_pool.free((uint32_t)info.session_id);
        }
        return create_status;
    }

    m_mirror_sessions[object_id] = info;
    m_mirror_session_count++;

    SWSS_LOG_NOTICE("Created mirror session %s, type=%d, sw_if_index=%u, is_erspan=%d, mirror session count: %d",
        sid.c_str(), mirror_type, info.sw_if_index, info.is_erspan, m_mirror_session_count);

    return SAI_STATUS_SUCCESS;
}

sai_status_t SwitchVpp::removeMirrorSession(
        _In_ sai_object_id_t object_id)
{
    SWSS_LOG_ENTER();

    auto it = m_mirror_sessions.find(object_id);
    if(it == m_mirror_sessions.end()) {
        SWSS_LOG_ERROR("Mirror session %s not found", sai_serialize_object_id(object_id).c_str());
        return SAI_STATUS_ITEM_NOT_FOUND;
    }

    MirrorSessionInfo &info = it->second;

    if(info.is_erspan) {
        // Remove the single-monitor-port pin (/32 host route via the resolved
        // nexthop) before tearing down the GRE tunnel.
        if(info.monitor_pinned) {
            pinErspanMonitor(info, false);
        }

        vpp_gre_tunnel_t tunnel{};
        // VPP locates the GRE tunnel to delete by its key (src, dst, fib, type,
        // session_id), not by instance or sw_if_index. We still pass the stored
        // instance for completeness, but the (src, dst, type, session_id) tuple
        // is what identifies the tunnel. type must match creation (ERSPAN = 2).
        tunnel.instance = info.gre_instance;
        tunnel.type = 2;
        tunnel.src = info.src_ip;
        tunnel.dst = info.dst_ip;
        tunnel.session_id = info.session_id;
        tunnel.outer_table_id = 0;

        uint32_t sw_if_index = 0;
        int ret = vpp_gre_tunnel_add_del(&tunnel, false, &sw_if_index);
        if(ret != 0) {
            // The VPP tunnel delete failed and is not retryable in a useful way
            // (a stuck tunnel stays stuck). Do NOT leak the session id or leave a
            // half-dead m_mirror_sessions entry behind: free the id and let the
            // erase below drop the entry so the id/OID can be reused cleanly.
            SWSS_LOG_ERROR("Failed to remove GRE tunnel for ERSPAN session, ret=%d; freeing session id and dropping entry anyway", ret);
        }

        // Recycle the ERSPAN session id. Done after the delete attempt so that,
        // on success, a re-allocation cannot collide with a still-live tunnel.
        m_erspan_session_id_pool.free((uint32_t)info.session_id);
    }

    m_mirror_sessions.erase(it);
    m_mirror_session_count--;
    SWSS_LOG_NOTICE("Removed mirror session entry %s, mirror session count: %d", sai_serialize_object_id(object_id).c_str(), m_mirror_session_count);

    CHECK_STATUS(remove_internal(SAI_OBJECT_TYPE_MIRROR_SESSION, sai_serialize_object_id(object_id)));
    SWSS_LOG_NOTICE("Removed mirror session %s from SAI DB", sai_serialize_object_id(object_id).c_str());

    return SAI_STATUS_SUCCESS;
}

sai_status_t SwitchVpp::pinErspanMonitor(
        _In_ MirrorSessionInfo &info,
        _In_ bool is_add)
{
    SWSS_LOG_ENTER();

    if (info.monitor_hwif.empty())
    {
        return SAI_STATUS_SUCCESS;
    }

    init_vpp_client();

    // Install (or remove) a /32 host route for the ERSPAN destination that
    // forwards via the resolved nexthop out the single monitor port. Routing
    // through the connected nexthop IP (rather than a static neighbor for the
    // mirror dst itself, which has no connected cover and would resolve to a
    // drop) makes VPP build a real rewrite adjacency; the GRE tunnel's outer
    // midchain then stacks on this /32, pinning the mirror to one stable port
    // and overriding the mirror-dst ECMP load-balance.
    vpp_ip_route_t *route = (vpp_ip_route_t *)
        calloc(1, sizeof(vpp_ip_route_t) + sizeof(vpp_ip_nexthop_t));
    if (!route)
    {
        SWSS_LOG_ERROR("ERSPAN monitor pin: failed to allocate route");
        return SAI_STATUS_FAILURE;
    }

    route->prefix_addr = info.dst_ip;
    route->prefix_len = (info.dst_ip.sa_family == AF_INET) ? 32 : 128;
    route->vrf_id = 0;
    route->is_multipath = false;
    route->nexthop_cnt = 1;

    sai_ip_address_t_to_vpp_ip_addr_t(info.monitor_nh, route->nexthop[0].addr);
    route->nexthop[0].sw_if_index = (uint32_t)~0;
    route->nexthop[0].hwif_name = info.monitor_hwif.c_str();
    route->nexthop[0].weight = 1;
    route->nexthop[0].preference = 0;
    route->nexthop[0].type = VPP_NEXTHOP_NORMAL;
    route->nexthop[0].flags = 0;

    int ret = ip_route_add_del(route, is_add);
    free(route);

    if (ret != 0)
    {
        SWSS_LOG_ERROR("ERSPAN monitor pin %s failed, ret=%d", (is_add ? "add" : "del"), ret);
        return SAI_STATUS_FAILURE;
    }

    return SAI_STATUS_SUCCESS;
}

bool SwitchVpp::resolveMonitorNexthop(
        _In_ sai_object_id_t monitor_port,
        _In_ const sai_mac_t mac,
        _Out_ sai_ip_address_t &nexthop)
{
    SWSS_LOG_ENTER();

    auto pit = m_port_neighbor_mac.find(monitor_port);
    if (pit == m_port_neighbor_mac.end())
    {
        return false;
    }

    std::string macStr = sai_serialize_mac(mac);

    // Find a neighbor on the monitor port whose L2 address matches the mirror
    // DST_MAC; that neighbor's IP is the ERSPAN nexthop orchagent resolved.
    for (const auto &kv : pit->second)
    {
        if (kv.second == macStr)
        {
            sai_deserialize_ip_address(kv.first, nexthop);
            return true;
        }
    }

    return false;
}

sai_status_t SwitchVpp::applyErspanMonitor(
        _In_ MirrorSessionInfo &info,
        _In_ sai_object_id_t monitor_port,
        _In_ const sai_mac_t mac)
{
    SWSS_LOG_ENTER();

    // Tear down any existing pin before (re)computing the target.
    if (info.monitor_pinned)
    {
        pinErspanMonitor(info, false);
        info.monitor_pinned = false;
    }

    std::string hwif;
    sai_ip_address_t nh;

    if (monitor_port != SAI_NULL_OBJECT_ID
        && vpp_get_hwif_name(monitor_port, 0, hwif)
        && resolveMonitorNexthop(monitor_port, mac, nh))
    {
        info.monitor_port = monitor_port;
        info.monitor_hwif = hwif;
        memcpy(info.monitor_mac, mac, sizeof(sai_mac_t));
        info.monitor_nh = nh;
        info.monitor_pinned = true;
        pinErspanMonitor(info, true);
        SWSS_LOG_NOTICE("ERSPAN monitor pinned: nexthop %s out %s",
            sai_serialize_ip_address(nh).c_str(), hwif.c_str());
    }
    else
    {
        // Monitor port or nexthop unresolved: record what we know for a later
        // re-point, but leave outer forwarding to the FIB (ECMP) for now.
        info.monitor_port = monitor_port;
        memcpy(info.monitor_mac, mac, sizeof(sai_mac_t));
        info.monitor_hwif.clear();
        info.monitor_pinned = false;
        SWSS_LOG_NOTICE("ERSPAN monitor port/nexthop unresolved; "
            "falling back to FIB-resolved forwarding for the mirror destination");
    }

    return SAI_STATUS_SUCCESS;
}

sai_status_t SwitchVpp::setMirrorSession(
        _In_ sai_object_id_t object_id,
        _In_ const sai_attribute_t *attr)
{
    SWSS_LOG_ENTER();

    auto sid = sai_serialize_object_id(object_id);

    auto it = m_mirror_sessions.find(object_id);

    // Only ERSPAN sessions carry a monitor-port pin. For everything else (and
    // for any attribute we don't specially handle) just persist to the SAI DB.
    if (attr != nullptr && it != m_mirror_sessions.end() && it->second.is_erspan)
    {
        MirrorSessionInfo &info = it->second;

        if (attr->id == SAI_MIRROR_SESSION_ATTR_MONITOR_PORT)
        {
            // orchagent re-resolved the ERSPAN next hop (the previously chosen
            // member left the ECMP group). Re-point using the current DST_MAC.
            applyErspanMonitor(info, attr->value.oid, info.monitor_mac);
            SWSS_LOG_NOTICE("ERSPAN session %s monitor port updated", sid.c_str());
        }
        else if (attr->id == SAI_MIRROR_SESSION_ATTR_DST_MAC_ADDRESS)
        {
            // The neighbor MAC of the resolved monitor port changed. Re-resolve
            // and re-point using the current monitor port.
            applyErspanMonitor(info, info.monitor_port, attr->value.mac);
            SWSS_LOG_NOTICE("ERSPAN session %s dst mac updated", sid.c_str());
        }
    }

    return set_internal(SAI_OBJECT_TYPE_MIRROR_SESSION, sid, attr);
}