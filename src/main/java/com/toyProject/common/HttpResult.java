package com.toyProject.common;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class HttpResult {

    private boolean success;
    private int status;
    private String data;
}
