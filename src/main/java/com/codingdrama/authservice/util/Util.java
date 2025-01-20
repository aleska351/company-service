package com.codingdrama.authservice.util;

import org.springframework.beans.BeanWrapper;
import org.springframework.beans.BeanWrapperImpl;

import java.beans.PropertyDescriptor;
import java.util.Arrays;

public class Util {
    
    /**
     * Returns an array of null property names from the input object.
     * @param object The object to check for null properties.
     * @return An array of null property names.
     */
    public static String[] getNullPropertyNames(Object object) {
        BeanWrapper src = new BeanWrapperImpl(object);
        return Arrays.stream(src.getPropertyDescriptors())
                       .map(PropertyDescriptor::getName)
                       .filter(name -> src.getPropertyValue(name) == null)
                       .toArray(String[]::new);
    }
}
