# Android-API-Security
Android API Security(.so)，安卓APP/API安全加密so库，防二次打包，防API签名破解

## 接入步骤

* 第一步：修改 app/src/main/cpp/apisecurity-lib.cpp 文件中的内容

```c++
//此处改为你的APP签名
#define SHA1 "a8e3d91a4f77dd7ccb8d43ee5046a4b6833f4785"
//此处改为你的APP包名
#define APP_PKG "cn.wzbos.android.sample"
//此处填写API盐值
#define API_SECRET "ABC"
```

* 第二步：修改 app/build.gradle 文件中的签名(测试需要，非必须)

```groovy
 signingConfigs {
        release {
            keyAlias 'wzbos'
            keyPassword '123456'
            storeFile file("test.keystore")
            storePassword '123456'
        }
    }
```

* 第三步：拷贝 app/build/intermediates/cmake/release/obj 文件夹下的.so文件到你的项目中libs文件夹中


## 依赖方式

在module级的build.gradle文件中加入以下代码

``` gradle

    sourceSets {
        main {
           jniLibs.srcDir 'libs'
        }
    }

    implementation project(":apisecurity")
```


## 调用示例

``` java
 //初始化
 APISecurity.init(context);
 //计算签名
 String val = "POST https://www.xxx.com/login?id=1&pwd=xxx......";
 String sign = MGAPISecurity.sign(aptStr)
```
