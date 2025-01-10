/*
 * Copyright © 2023 THALES. All rights reserved.
 */

package com.thales.attest;

import android.os.Handler;
import android.os.Looper;

import androidx.annotation.NonNull;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class ThreadUtils {
    private static final ExecutorService BACKGROUND_THREAD_EXECUTOR = Executors.newCachedThreadPool();
    private static final Handler MAIN_THREAD_HANDLER = new Handler(Looper.getMainLooper());

    public static ExecutorService getBackgroundThreadExecutor() {
        return BACKGROUND_THREAD_EXECUTOR;
    }

    public static Handler getMainThreadHandler() {
        return MAIN_THREAD_HANDLER;
    }

    public static <T> Callback<T> wrapD1TaskCallbackInMainThread(final Callback<T> callback) {
        return new Callback<T>() {
            @Override
            public void onSuccess(final T data) {
                getMainThreadHandler().post(new Runnable() {
                    @Override
                    public void run() {
                        if (callback != null) { callback.onSuccess(data); }
                    }
                });
            }

            @Override
            public void onError(final Exception exception) {
                getMainThreadHandler().post(new Runnable() {
                    @Override
                    public void run() {
                        if (callback != null) { callback.onError(exception); }
                    }
                });
            }
        };
    }

    public interface Callback<T> {
        void onSuccess(T data);

        void onError(@NonNull Exception exception);
    }
}
