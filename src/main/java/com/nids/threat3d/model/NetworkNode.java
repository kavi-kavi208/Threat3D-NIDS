package com.nids.threat3d.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

@Entity
@Table(name = "network_nodes")
public class NetworkNode {

    @Id
    @Column(nullable = false, length = 64)
    private String id;

    @Column(nullable = false, length = 128)
    private String label;

    @Column(nullable = false, unique = true, length = 64)
    private String ipAddress;

    @Column(length = 64)
    private String macAddress;

    @Column(nullable = false, length = 32)
    private String nodeType; // FIREWALL, ROUTER, WEB_SERVER, DB_SERVER, AUTH_SERVER, WORKSTATION, ATTACKER

    @Column(length = 64)
    private String subnet;

    @Column(nullable = false)
    private float posX;

    @Column(nullable = false)
    private float posY;

    @Column(nullable = false)
    private float posZ;

    @Column(nullable = false, length = 32)
    private String status; // HEALTHY, SUSPICIOUS, COMPROMISED, ISOLATED

    @Column(length = 128)
    private String openPorts;

    @Column(nullable = false)
    private LocalDateTime lastSeen = LocalDateTime.now();

    public NetworkNode() {
    }

    public NetworkNode(String id, String label, String ipAddress, String macAddress,
                       String nodeType, String subnet, float posX, float posY, float posZ,
                       String status, String openPorts) {
        this.id = id;
        this.label = label;
        this.ipAddress = ipAddress;
        this.macAddress = macAddress;
        this.nodeType = nodeType;
        this.subnet = subnet;
        this.posX = posX;
        this.posY = posY;
        this.posZ = posZ;
        this.status = status;
        this.openPorts = openPorts;
        this.lastSeen = LocalDateTime.now();
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getLabel() {
        return label;
    }

    public void setLabel(String label) {
        this.label = label;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }

    public String getMacAddress() {
        return macAddress;
    }

    public void setMacAddress(String macAddress) {
        this.macAddress = macAddress;
    }

    public String getNodeType() {
        return nodeType;
    }

    public void setNodeType(String nodeType) {
        this.nodeType = nodeType;
    }

    public String getSubnet() {
        return subnet;
    }

    public void setSubnet(String subnet) {
        this.subnet = subnet;
    }

    public float getPosX() {
        return posX;
    }

    public void setPosX(float posX) {
        this.posX = posX;
    }

    public float getPosY() {
        return posY;
    }

    public void setPosY(float posY) {
        this.posY = posY;
    }

    public float getPosZ() {
        return posZ;
    }

    public void setPosZ(float posZ) {
        this.posZ = posZ;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getOpenPorts() {
        return openPorts;
    }

    public void setOpenPorts(String openPorts) {
        this.openPorts = openPorts;
    }

    public LocalDateTime getLastSeen() {
        return lastSeen;
    }

    public void setLastSeen(LocalDateTime lastSeen) {
        this.lastSeen = lastSeen;
    }
}
