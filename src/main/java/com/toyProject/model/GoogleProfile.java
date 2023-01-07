package com.toyProject.model;

import lombok.Data;

@Data
public class GoogleProfile {

    public String sub;
    public String name;
    public String given_name;
    public String family_name;
    public String picture;
    public String email;
    public boolean email_verified;
    public String locale;
}
