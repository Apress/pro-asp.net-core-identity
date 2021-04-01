using System;
using System.Collections;
using System.Collections.Generic;

namespace ExampleApp.Identity {

    public static class StoreClassExtentions {

        public static T UpdateFrom<T>(this T target, T source) {
            UpdateFrom(target, source, out bool discardValue);
            return target;
        }

        public static T UpdateFrom<T>(this T target, T source, out bool changes) {
            object value;
            int changeCount = 0;
            Type classType = typeof(T);
            foreach (var prop in classType.GetProperties()) {
                if (prop.PropertyType.IsGenericType &&
                    prop.PropertyType.GetGenericTypeDefinition()
                        .Equals(typeof(IList<>))) {
                    Type listType = typeof(List<>).MakeGenericType(prop.PropertyType
                        .GetGenericArguments()[0]);
                    IList sourceList = prop.GetValue(source) as IList;
                    if (sourceList != null) {
                        prop.SetValue(target, Activator.CreateInstance(listType,
                            sourceList));
                    }
                } else {
                    if ((value = prop.GetValue(source)) != null
                            && !value.Equals(prop.GetValue(target))) {
                        classType.GetProperty(prop.Name).SetValue(target, value);
                        changeCount++;
                    }
                }
            }
            changes = changeCount > 0;
            return target;
        }

        public static T Clone<T>(this T original) =>
             Activator.CreateInstance<T>().UpdateFrom(original);
    }
}
