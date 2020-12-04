package com.google.jimlongja.attestprops.Utils;

import java.lang.reflect.InvocationTargetException;

public class ReflectionUtil {

    /**
     * Calls a method on an object with the given arguments. This can be used when the method is not
     * in the SDK. If any arguments are {@code null} or primitive types you must use
     * {@link #invoke(Object, String, Class[], Object...)} to avoid {@link NullPointerException}s
     * and autoboxing respectively.
     *
     * ReflectionUtil.invoke(dpm, "clearDeviceOwnerApp", "com.example.deviceowner");
     *
     * @param obj        The object to call the method on.
     * @param methodName The name of the method.
     * @param args       The arguments to pass to the method. Ensure they are of the same type as
     *                   the method parameters. If they are not, use the more verbose
     *                   {@link #invoke(Object, String, Class[], Object[])}.
     * @return           The result of the invocation. {@code null} if {@code void}.
     */
    static Object invoke(Object obj, String methodName, Object... args)
            throws ReflectionIsTemporaryException {
        return invoke(obj.getClass(), obj, methodName, args);
    }

    /**
     * Same as {@link #invoke(Object, String, Object...)} but for static methods.
     */
    static Object invoke(Class<?> clazz, String methodName, Object... args)
            throws ReflectionIsTemporaryException {
        return invoke(clazz, null, methodName, args);
    }

    /**
     * Calls a method on an object with the given arguments. This can be used when the method is not
     * in the SDK. Consider using {@link #invoke(Object, String, Object...)} for less verbosity if
     * the arguments are the same type as the method parameters (subclasses don't work).
     *
     * ReflectionUtil.invoke(dpm, "wipeData", new Class<?>[] {int.class},
     *         ReflectionUtil.intConstant(DevicePolicyManager.class, "WIPE_EXTERNAL_STORAGE"));
     *
     * @param obj            The object to call the method on.
     * @param methodName     The name of the method.
     * @param parameterTypes The method parameter types.
     * @param args           The arguments to pass to the method.
     * @return               The result of the invocation. {@code null} if {@code void}.
     */
    public static Object invoke(Object obj, String methodName, Class<?>[] parameterTypes,
                         Object... args) throws ReflectionIsTemporaryException {
        return invoke(obj.getClass(), obj, methodName, parameterTypes, args);
    }

    /**
     * Same as {@link #invoke(Object, String, Class[], Object...)} but for static methods.
     */
    static Object invoke(Class<?> clazz, String methodName, Class<?>[] parameterTypes,
                         Object... args) throws ReflectionIsTemporaryException {
        return invoke(clazz, null, methodName, parameterTypes, args);
    }

    /** Resolve the parameter types and invoke the method. */
    private static Object invoke(Class<?> clazz, Object obj, String methodName, Object... args)
            throws ReflectionIsTemporaryException {
        Class<?>[] parameterTypes = new Class<?>[args.length];
        for (int i = 0; i < args.length; ++i) {
            parameterTypes[i] = args[i].getClass();
        }
        return invoke(clazz, obj, methodName, parameterTypes, args);
    }

    /** Resolve the method and invoke it. */
    private static Object invoke(Class<?> clazz, Object obj, String methodName,
                                 Class<?>[] parameterTypes, Object... args)
            throws ReflectionIsTemporaryException {
        try {
            return clazz.getMethod(methodName, parameterTypes).invoke(obj, args);
        } catch (SecurityException | NoSuchMethodException | IllegalArgumentException
                | IllegalAccessException | InvocationTargetException e) {
            throw new ReflectionIsTemporaryException("Failed to invoke method", e);
        }
    }

    /**
     * Gets the value of a static int constant. This can be used when the constant is not yet in the
     * SDK.
     *
     * ReflectionUtil.intConstant(DevicePolicyManager.class, "WIPE_EXTERNAL_STORAGE");
     *
     * @param clazz     The class that contains the constant.
     * @param fieldName The name of the constant field.
     * @return          The value of the constant.
     */
    static int intConstant(Class<?> clazz, String fieldName)
            throws ReflectionIsTemporaryException {
        try {
            return clazz.getField(fieldName).getInt(null);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new ReflectionIsTemporaryException("Failed to retrieve constant", e);
        }
    }

    /**
     * Gets the value of a static string constant. This can be used when the constant is not yet in
     * the SDK.
     *
     * ReflectionUtil.stringConstant(DevicePolicyManager.class, "ACTION_ADD_DEVICE_ADMIN");
     *
     * @param clazz     The class that contains the constant.
     * @param fieldName The name of the constant field.
     * @return          The value of the constant.
     */
    static String stringConstant(Class<?> clazz, String fieldName)
            throws ReflectionIsTemporaryException {
        try {
            return (String) clazz.getField(fieldName).get(null);
        } catch (NoSuchFieldException | IllegalAccessException e) {
            throw new ReflectionIsTemporaryException("Failed to retrieve constant", e);
        }
    }

    /**
     * Thrown when the temporary use of reflection fails to find and use a new API.
     *
     * This will happen when the API is not yet available in the SDK and TestDPC is running on
     * device that isn't running the latest version of the framework and therefore doesn't support
     * the API.
     *
     * To handle this, gracefully fail the operation in progress.
     */
    public static class ReflectionIsTemporaryException extends Exception {
        ReflectionIsTemporaryException(String message, Throwable cause) {
            super(message, cause);
        }
    }
}
