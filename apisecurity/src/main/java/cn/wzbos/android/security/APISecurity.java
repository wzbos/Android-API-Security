package cn.wzbos.android.security;

import android.content.Context;

public class APISecurity {
    static {
        System.loadLibrary("apisecurity-lib");
    }

    public static native String sign(String str);

    public static native boolean init(Context context);
}

