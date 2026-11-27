package com.rf.demo;

import android.app.Activity;
import android.os.Bundle;
import android.widget.TextView;

/** 启动入口一：Activity。校验不过直接 finish()，模拟"程序起不来"。 */
public class MainActivity extends Activity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        TextView tv = new TextView(this);
        if (!LicenseManager.verify(this)) {
            tv.setText("授权失败：卡密无效或已到期");
            setContentView(tv);
            finish();
            return;
        }
        tv.setText("已授权");
        setContentView(tv);
    }
}
