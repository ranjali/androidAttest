plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.jetbrains.kotlin.android)
}

android {
    namespace = "com.thales.attest"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.thales.attest"
        minSdk = 34
        targetSdk = 35
        versionCode = 1
        versionName = "1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        vectorDrawables {
            useSupportLibrary = true
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
    buildFeatures {
        compose = true
    }
    composeOptions {
        kotlinCompilerExtensionVersion = "1.5.1"
    }
    packaging {
        resources {
            excludes += "/META-INF/{AL2.0,LGPL2.1}"
            excludes += "META-INF/versions/9/OSGI-INF/MANIFEST.MF"
        }
    }
}

dependencies {

    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.lifecycle.runtime.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.ui)
    implementation(libs.androidx.ui.graphics)
    implementation(libs.androidx.ui.tooling.preview)
    implementation(libs.androidx.material3)

    // Jackson core libraries
    implementation("com.fasterxml.jackson.core:jackson-databind:2.18.2") // Replace with the latest version
    implementation("com.fasterxml.jackson.core:jackson-core:2.18.2") // Replace with the latest version

    // Jackson CBOR module
    implementation("com.fasterxml.jackson.dataformat:jackson-dataformat-cbor:2.18.2") // Replace with the latest version

    implementation(libs.bouncycastle.bcpkix.jdk180n)
    implementation(libs.bouncycastle.bcprov.jdk180n)
    implementation(libs.protobuf.javalite)
    implementation(libs.guava.jre)
    api(libs.google.auto.annotations)
//    api(libs.google.auto.factory)
    annotationProcessor(libs.google.auto)
    implementation(libs.google.gson)
    implementation(libs.errorprone)
    implementation(libs.okhttp)

    testImplementation(libs.junit)
    androidTestImplementation(libs.androidx.junit)
    androidTestImplementation(libs.androidx.espresso.core)
    androidTestImplementation(platform(libs.androidx.compose.bom))
    androidTestImplementation(libs.androidx.ui.test.junit4)
    debugImplementation(libs.androidx.ui.tooling)
    debugImplementation(libs.androidx.ui.test.manifest)
}