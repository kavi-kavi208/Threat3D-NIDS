package com.nids.threat3d.model;

/**
 * Role-Based Access Control (RBAC) definitions.
 * - ADMIN: Full access to system configuration, rules, node controls, and user management.
 * - ANALYST: Access to 3D SOC visualization, packet inspector, threat alerts, and report downloads.
 * - STUDENT: Access to educational guidance lab, attack simulations, and cyber defense quizzes.
 */
public enum Role {
    ROLE_ADMIN,
    ROLE_ANALYST,
    ROLE_STUDENT
}
