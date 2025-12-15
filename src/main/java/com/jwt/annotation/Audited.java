package com.jwt.annotation;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ElementType.METHOD})
@Retention(RetentionPolicy.RUNTIME)
public @interface Audited {
    int index() default 0;

    boolean shouldStoreAll() default false;

    String[] fieldsToAudit() default {};

    Identifier identifier() default Identifier.NONE;

    String identifierKey() default "";

    String activity() default "";
}
