package cn.wzbos.android.sample;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.TextView;


import cn.wzbos.android.security.APISecurity;

public class MainActivity extends AppCompatActivity {

    TextView tv;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        tv = findViewById(R.id.sample_text);

        APISecurity.init(MainActivity.this);

        findViewById(R.id.btnTest).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                //API签名字符串
                String val = "POST https://www.xxx.com/login?id=1&pwd=xxx......";
                tv.setText("Sign:" + APISecurity.sign(val));
            }
        });
    }
}
