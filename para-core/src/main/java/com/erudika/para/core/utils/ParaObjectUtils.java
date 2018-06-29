/*
 * Copyright 2013-2017 Erudika. https://erudika.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * For issues and patches go to: https://github.com/erudika
 */
package com.erudika.para.core.utils;

import com.erudika.para.annotations.Stored;
import com.erudika.para.core.App;
import com.erudika.para.core.ParaObject;
import com.erudika.para.core.Sysprop;
import com.erudika.para.utils.Config;
import com.erudika.para.utils.Utils;
import static com.erudika.para.utils.Utils.getAllDeclaredFields;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.ObjectReader;
import com.fasterxml.jackson.databind.ObjectWriter;
import com.fasterxml.jackson.databind.SerializationFeature;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.sql.Timestamp;
import java.text.SimpleDateFormat;
import java.util.*;

import org.apache.commons.beanutils.BeanUtils;
import org.apache.commons.beanutils.PropertyUtils;
import org.apache.commons.collections.bidimap.DualHashBidiMap;
import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.type.filter.AssignableTypeFilter;
import org.springframework.util.ClassUtils;

/**
 * Contains methods for object/grid mapping, JSON serialization, class scanning and resolution.
 * @author Alex Bogdanovski [alex@erudika.com]
 */
@SuppressWarnings("unchecked")
public final class ParaObjectUtils {

	private static final Logger logger = LoggerFactory.getLogger(ParaObjectUtils.class);
	// maps plural to singular type definitions
	private static final Map<String, String> CORE_TYPES = new DualHashBidiMap();
	// maps lowercase simple names to class objects
	private static final Map<String, Class<? extends ParaObject>> CORE_CLASSES = new DualHashBidiMap();

	private static final Map<String, Map<String, Field>> typeFieldMap = new HashMap<>();
	private static final Timestamp epoch = new Timestamp(0L);
	// private static final String searchDateFormat = "yyyy-MM-dd'T'HH:mm:ss.SSSZ||yyyy-MM-dd'T'HH:mm:ssZ||yyyy-MM-dd'T'HH:mmZ||yyyy-MM-dd'T'HH:mm:ss.SSS||yyyy-MM-dd'T'HH:mm:ss||yyyy-MM-dd'T'HH:mm||yyyy-MM-dd HH:mm:ss.SSS||yyyy-MM-dd HH:mm:ss||yyyy-MM-dd HH:mm||yyyy-MM-dd||yyyy/MM/dd||yyyyMMdd||yyyyMM||yyyy-MM||yyyy/MM||yyyy||epoch_millis||epoch_second";
	private static final String searchDateFormat = "yyyy-MM-dd HH:mm:ss.SSS||yyyy-MM-dd HH:mm:ss||yyyy-MM-dd HH:mm||yyyy-MM-dd||yyyy/MM/dd||yyyyMMdd||yyyyMM||yyyy-MM||yyyy/MM||yyyy||epoch_millis||epoch_second";

	private static final CoreClassScanner SCANNER = new CoreClassScanner();
	private static final ObjectMapper JSON_MAPPER = new ObjectMapper();
	private static final ObjectReader JSON_READER;
	private static final ObjectWriter JSON_WRITER;

	static {
		JSON_MAPPER.disable(SerializationFeature.FAIL_ON_EMPTY_BEANS);
		JSON_MAPPER.disable(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES);
		JSON_MAPPER.enable(DeserializationFeature.ACCEPT_EMPTY_STRING_AS_NULL_OBJECT);
		JSON_MAPPER.enable(SerializationFeature.INDENT_OUTPUT);
		JSON_MAPPER.setSerializationInclusion(JsonInclude.Include.NON_NULL);
		JSON_READER = JSON_MAPPER.reader();
		JSON_WRITER = JSON_MAPPER.writer();
	}

	private ParaObjectUtils() { }

	/**
	 * A Jackson {@code ObjectMapper}.
	 *
	 * @return JSON object mapper
	 */
	public static ObjectMapper getJsonMapper() {
		return JSON_MAPPER;
	}

	/**
	 * A Jackson JSON reader.
	 *
	 * @param type the type to read
	 * @return JSON object reader
	 */
	public static ObjectReader getJsonReader(Class<?> type) {
		return JSON_READER.forType(type);
	}

	/**
	 * A Jackson JSON writer. Pretty print is on.
	 *
	 * @return JSON object writer
	 */
	public static ObjectWriter getJsonWriter() {
		return JSON_WRITER;
	}

	/**
	 * A Jackson JSON writer. Pretty print is off.
	 *
	 * @return JSON object writer with indentation disabled
	 */
	public static ObjectWriter getJsonWriterNoIdent() {
		return JSON_WRITER.without(SerializationFeature.INDENT_OUTPUT);
	}

	/////////////////////////////////////////////
	//	     OBJECT MAPPING & CLASS UTILS
	/////////////////////////////////////////////

	/**
	 * Returns a map of the core data types.
	 * @return a map of type plural - type singular form
	 */
	public static Map<String, String> getCoreTypes() {
		if (CORE_TYPES.isEmpty()) {
			try {
				for (Class<? extends ParaObject> clazz : ParaObjectUtils.getCoreClassesMap().values()) {
					ParaObject p = clazz.newInstance();
					CORE_TYPES.put(p.getPlural(), p.getType());
				}
			} catch (Exception ex) {
				logger.error(null, ex);
			}
		}
		return Collections.unmodifiableMap(CORE_TYPES);
	}

	/**
	 * Returns a map of all registered types.
	 * @param app the app to search for custom types
	 * @return a map of plural - singular form of type names
	 */
	public static Map<String, String> getAllTypes(App app) {
		Map<String, String> map = new HashMap<>(getCoreTypes());
		if (app != null) {
			map.putAll(app.getDatatypes());
		}
		return map;
	}

	/**
	 * Checks if the type of an object matches its real Class name.
	 *
	 * @param so an object
	 * @return true if the types match
	 */
	public static boolean typesMatch(ParaObject so) {
		return (so == null) ? false : so.getClass().equals(toClass(so.getType()));
	}

	/**
	 * @see #getAnnotatedFields(com.erudika.para.core.ParaObject, java.lang.Class, boolean)
	 * @param <P> the object type
	 * @param pojo the object to convert to a map
	 * @return a map of fields and their values
	 */
	public static <P extends ParaObject> Map<String, Object> getAnnotatedFields(P pojo) {
		return getAnnotatedFields(pojo, null);
	}

	/**
	 * @see #getAnnotatedFields(com.erudika.para.core.ParaObject, java.lang.Class, boolean)
	 * @param <P> the object type
	 * @param pojo the object to convert to a map
	 * @param filter a filter annotation. fields that have it will be skipped
	 * @return a map of fields and their values
	 */
	public static <P extends ParaObject> Map<String, Object> getAnnotatedFields(P pojo,
			Class<? extends Annotation> filter) {
		return getAnnotatedFields(pojo, filter, true);
	}

	/**
	 * @see #getAnnotatedFields(com.erudika.para.core.ParaObject, java.lang.Class, boolean)
	 * @param <P> the object type
	 * @param pojo the object to convert to a map
	 * @param flattenNestedObjectsToString flattens nested objects to a JSON string, true by default.
	 * @return a map of fields and their values
	 */
	public static <P extends ParaObject> Map<String, Object> getAnnotatedFields(P pojo,
			boolean flattenNestedObjectsToString) {
		return getAnnotatedFields(pojo, null, flattenNestedObjectsToString);
	}

	/**
	 * Returns a map of annotated fields of a domain object. Only annotated fields are returned. This method forms the
	 * basis of an Object/Grid Mapper. It converts an object to a map of key/value pairs. That map can later be
	 * persisted to a data store.
	 * <br>
	 * If {@code flattenNestedObjectsToString} is true all field values that are objects (i.e. not primitive types or
	 * wrappers) are converted to a JSON string otherwise they are left as they are and will be serialized as regular
	 * JSON objects later (structure is preserved). Null is considered a primitive type. Transient fields and
	 * serialVersionUID are skipped.
	 *
	 * @param <P> the object type
	 * @param pojo the object to convert to a map
	 * @param filter a filter annotation. fields that have it will be skipped
	 * @param flattenNestedObjectsToString true if you want to flatten the nested objects to a JSON string.
	 * @return a map of fields and their values
	 */
	public static <P extends ParaObject> Map<String, Object> getAnnotatedFields(P pojo,
			Class<? extends Annotation> filter, boolean flattenNestedObjectsToString) {
		HashMap<String, Object> map = new HashMap<>();
		if (pojo == null) {
			return map;
		}
		try {
			List<Field> fields = getAllDeclaredFields(pojo.getClass());
			// filter transient fields and those without annotations
			for (Field field : fields) {
				boolean dontSkip = ((filter == null) ? true : !field.isAnnotationPresent(filter));
				if (field.isAnnotationPresent(Stored.class) && dontSkip) {
					String name = field.getName();
					Object value = PropertyUtils.getProperty(pojo, name);
					if ("properties".equals(name)) {
						map.putAll((Map) value);
					} else {
						if (!(value == null || (value instanceof List && ((List) value).isEmpty()) || (value instanceof Map && ((Map) value).isEmpty()))) {
							if (!Utils.isBasicType(field.getType()) && flattenNestedObjectsToString) {
								value = getJsonWriterNoIdent().writeValueAsString(value);
							}
							JsonProperty annotation = field.getAnnotation(JsonProperty.class);
							if(annotation!=null){
								name = annotation.value();
							}
							map.put(name, value);
						}
					}
				}
			}

			for(Map.Entry<String, Object> entry: map.entrySet()) {
				if (entry.getValue() instanceof Map) {
					entry.setValue(getJsonWriterNoIdent().writeValueAsString(entry.getValue()));
				} else if (entry.getValue() instanceof List) {
					List list = (List) entry.getValue();
					boolean hasComplexType = false;
					for (Object object: list) {
						if (object != null && (object instanceof Map || object instanceof List || !Utils.isBasicType(object.getClass()))) {
							hasComplexType = true;
						}
					}
					if (hasComplexType) {
						entry.setValue(getJsonWriterNoIdent().writeValueAsString(entry.getValue()));
					}
				}
			}
		} catch (Exception ex) {
			logger.error(null, ex);
		}

		return Collections.unmodifiableMap(map);
	}

	/**
	 * @see #setAnnotatedFields(com.erudika.para.core.ParaObject, java.util.Map, java.lang.Class)
	 * @param <P> the object type
	 * @param data the map of fields/values
	 * @return the populated object
	 */
	public static <P extends ParaObject> P setAnnotatedFields(Map<String, Object> data) {
		return setAnnotatedFields(null, data, null);
	}

	/**
	 * Converts a map of fields/values to a domain object. Only annotated fields are populated. This method forms the
	 * basis of an Object/Grid Mapper.
	 * <br>
	 * Map values that are JSON objects are converted to their corresponding Java types. Nulls and primitive types are
	 * preserved.
	 *
	 * @param <P> the object type
	 * @param pojo the object to populate with data
	 * @param data the map of fields/values
	 * @param filter a filter annotation. fields that have it will be skipped
	 * @return the populated object
	 */
	public static <P extends ParaObject> P setAnnotatedFields(P pojo, Map<String, Object> data,
			Class<? extends Annotation> filter) {
		if (data == null || data.isEmpty()) {
			return null;
		}
		try {
			if (pojo == null) {
				// try to find a declared class in the core package
				pojo = (P) toClass((String) data.get(Config._TYPE)).getConstructor().newInstance();
			}
			List<Field> fields = getAllDeclaredFields(pojo.getClass());
			Map<String, Object> props = new HashMap<>(data);
			for (Field field : fields) {
				boolean dontSkip = ((filter == null) ? true : !field.isAnnotationPresent(filter));
				String name = field.getName();
				JsonProperty annotation = field.getAnnotation(JsonProperty.class);
				String jsonName = name;
				if(annotation!=null){
					jsonName = annotation.value();
				}
				Object value = data.get(jsonName);
				if (field.isAnnotationPresent(Stored.class) && dontSkip) {
					// try to read a default value from the bean if any
					if (value == null && PropertyUtils.isReadable(pojo, name)) {
						value = PropertyUtils.getProperty(pojo, name);
					}
					// handle complex JSON objects deserialized to Maps, Arrays, etc.
					if (!Utils.isBasicType(field.getType()) && value instanceof String) {
						// in this case the object is a flattened JSON string coming from the DB
						value = getJsonReader(field.getType()).readValue(value.toString());
					}
					field.setAccessible(true);
					BeanUtils.setProperty(pojo, name, value);
				}
				props.remove(jsonName);
			}
			// handle unknown (user-defined) fields
			setUserDefinedProperties(pojo, props);
		} catch (Exception ex) {
			logger.error(null, ex);
			pojo = null;
		}
		return pojo;
	}

	/**
	 * Handles "unknown" or user-defined fields. The Para object is populated with custom fields
	 * which are stored within the "properties" field of {@link Sysprop}. Unknown or user-defined properties are
	 * those which are not declared inside a Java class, but come from an API request.
	 * @param pojo a Para object
	 * @param props properties to apply to the object.
	 */
	private static <P> void setUserDefinedProperties(P pojo, Map<String, Object> props) {
		if (props != null && pojo instanceof Sysprop) {
			for (Map.Entry<String, Object> entry : props.entrySet()) {
				String name = entry.getKey();
				Object value = entry.getValue();
				// handle the case where we have custom user-defined properties
				// which are not defined as Java class fields
				//if (!PropertyUtils.isReadable(pojo, name)) {
					if (value != null && value instanceof String) {
						String str = ((String) value).trim();
						if (str.length() < 1) {
							value = null;
						} else if(str.charAt(0) == '{' || str.charAt(0) == '[') {
							try {
								value = getJsonReader(str.charAt(0) == '{' ? Map.class : List.class).readValue((String) value);
							} catch (IOException ignored) {
							}
						}
					}

					if (value == null) {
						((Sysprop) pojo).removeProperty(name);
					} else {
						((Sysprop) pojo).addProperty(name, value);
					}
				//}
			}
		}
	}

	/**
	 * Constructs a new instance of a core object.
	 *
	 * @param <P> the object type
	 * @param type the simple name of a class
	 * @return a new instance of a core class. Defaults to {@link com.erudika.para.core.Sysprop}.
	 * @see #toClass(java.lang.String)
	 */
	public static <P extends ParaObject> P toObject(String type) {
		try {
			return (P) toClass(type).getConstructor().newInstance();
		} catch (Exception ex) {
			logger.error(null, ex);
			return null;
		}
	}

	/**
	 * Converts a class name to a real Class object.
	 *
	 * @param type the simple name of a class
	 * @return the Class object or {@link com.erudika.para.core.Sysprop} if the class was not found.
	 * @see java.lang.Class#forName(java.lang.String)
	 */
	public static Class<? extends ParaObject> toClass(String type) {
		return toClass(type, Sysprop.class);
	}

	/**
	 * Converts a class name to a real {@link com.erudika.para.core.ParaObject} subclass. Defaults to
	 * {@link com.erudika.para.core.Sysprop} if the class was not found in the core package path.
	 *
	 * @param type the simple name of a class
	 * @param defaultClass returns this type if the requested class was not found on the classpath.
	 * @return the Class object. Returns null if defaultClass is null.
	 * @see java.lang.Class#forName(java.lang.String)
	 * @see com.erudika.para.core.Sysprop
	 */
	public static Class<? extends ParaObject> toClass(String type, Class<? extends ParaObject> defaultClass) {
		Class<? extends ParaObject> returnClass = defaultClass;
		if (StringUtils.isBlank(type) || !getCoreClassesMap().containsKey(type)) {
			return returnClass;
		}
		return getCoreClassesMap().get(type);
	}

	/**
	 * Searches through the Para core package and {@code Config.CORE_PACKAGE_NAME} package for {@link ParaObject}
	 * subclasses and adds their names them to the map.
	 *
	 * @return a map of simple class names (lowercase) to class objects
	 */
	public static Map<String, Class<? extends ParaObject>> getCoreClassesMap() {
		if (CORE_CLASSES.isEmpty()) {
			try {
				Set<Class<? extends ParaObject>> s = SCANNER.getComponentClasses(ParaObject.class.getPackage().getName());
				if (!Config.CORE_PACKAGE_NAME.isEmpty()) {
					Set<Class<? extends ParaObject>> s2 = SCANNER.getComponentClasses(Config.CORE_PACKAGE_NAME);
					s.addAll(s2);
				}

				s.addAll(SCANNER.getComponentClasses("cn.abrain.baas.met.entity"));

				for (Class<? extends ParaObject> coreClass : s) {
					boolean isAbstract = Modifier.isAbstract(coreClass.getModifiers());
					boolean isInterface = Modifier.isInterface(coreClass.getModifiers());
					boolean isCoreObject = ParaObject.class.isAssignableFrom(coreClass);
					if (isCoreObject && !isAbstract && !isInterface) {
						CORE_CLASSES.put(toKey(coreClass), coreClass);
					}
				}
				logger.debug("Found {} ParaObject classes: {}", CORE_CLASSES.size(), CORE_CLASSES);
			} catch (Exception ex) {
				logger.error(null, ex);
			}
		}
		return Collections.unmodifiableMap(CORE_CLASSES);
	}

	public static String toKey(Class<? extends ParaObject> coreClass) {
		if (coreClass == null) {
			return "";
		}

		String fullName = coreClass.getName();
		String simpleName = coreClass.getSimpleName();
		if(fullName.startsWith("cn.abrain.baas.rbac.entity.ldc")) {
			char[] chars = simpleName.toCharArray();
			StringBuffer sb = new StringBuffer();
			for (char c : chars) {
				if (Character.isUpperCase(c)) {
					sb.append("_").append(c);
				} else {
					sb.append(Character.toUpperCase(c));
				}
			}
			return sb.substring(1, sb.length());
		} else  if (fullName.startsWith("cn.abrain.baas.met.entity")) {
			return simpleName;
		} else if (fullName.startsWith("cn.abrain")) {
			char[] chars = simpleName.toCharArray();
			chars[0] = Character.toLowerCase(chars[0]);
			return new String(chars);
		} else {
			return simpleName.toLowerCase();
		}
	}
	
	/**
	 * Helper class that lists all classes contained in a given package.
	 */
	private static class CoreClassScanner extends ClassPathScanningCandidateComponentProvider {

		private static final Logger LOG = LoggerFactory.getLogger(CoreClassScanner.class);

		CoreClassScanner() {
			super(false);
			addIncludeFilter(new AssignableTypeFilter(ParaObject.class));
		}

		public final Set<Class<? extends ParaObject>> getComponentClasses(String basePackage) {
			basePackage = (basePackage == null) ? "" : basePackage;
			Set<Class<? extends ParaObject>> classes = new HashSet<>();
			for (BeanDefinition candidate : findCandidateComponents(basePackage)) {
				try {
					Class<? extends ParaObject> cls = (Class<? extends ParaObject>)
							ClassUtils.resolveClassName(candidate.getBeanClassName(),
									Thread.currentThread().getContextClassLoader());
					classes.add(cls);
				} catch (Exception ex) {
					LOG.error(null, ex);
				}
			}
			return classes;
		}
	}

	/**
	 * Converts a JSON string to a domain object. If we can't match the JSON to a core object, we fall back to
	 * {@link com.erudika.para.core.Sysprop}.
	 *
	 * @param <P> type of object to convert
	 * @param json the JSON string
	 * @return a core domain object or null if the string was blank
	 */
	public static <P extends ParaObject> P fromJSON(String json) {
		if (StringUtils.isBlank(json)) {
			return null;
		}
		try {
			Map<String, Object> map = getJsonReader(Map.class).readValue(json);
			return setAnnotatedFields(map);
		} catch (Exception e) {
			logger.error(null, e);
		}
		return null;
	}

	/**
	 * Converts a domain object to JSON.
	 *
	 * @param <P> type of object to convert
	 * @param obj a domain object
	 * @return the JSON representation of that object
	 */
	public static <P extends ParaObject> String toJSON(P obj) {
		if (obj == null) {
			return "{}";
		}
		try {
			return getJsonWriter().writeValueAsString(obj);
		} catch (Exception e) {
			logger.error(null, e);
		}
		return "{}";
	}

	public static <P extends ParaObject> P newParaObjectInstance(String type) {
		try {
			return (P) ParaObjectUtils.toClass(type).getConstructor().newInstance();
		} catch (ReflectiveOperationException e) {
			logger.error("Reflective operation failed: {}", e.getMessage(), e);
			throw new Error(e);
		}
	}

	public static Map<String, Field> getFieldMap(String type) {
		if (StringUtils.isBlank(type)) {
			type = "sysprop";
		}
		Map<String, Field> fieldMap = typeFieldMap.get(type);
		if (fieldMap == null || fieldMap.isEmpty()) {
			fieldMap = new HashMap<>();
			List<Field> fieldList = Utils.getAllDeclaredFields(ParaObjectUtils.toClass(type));
			for (Field field : fieldList) {
				if (field.getAnnotation(Stored.class) != null) {
					fieldMap.put(field.getName(), field);
					JsonProperty jsonName = field.getAnnotation(JsonProperty.class);
					if (jsonName != null) {
						fieldMap.put(jsonName.value(), field);
					}
				}
			}
			synchronized (typeFieldMap) {
				typeFieldMap.put(type, fieldMap);
			}
		}
		return fieldMap;
	}

	public static Object getProperty(ParaObject po, String name) {
		if (po == null || name == null || name.isEmpty()) {
			return null;
		}

		if (name.startsWith("properties.")) {
			name = name.substring(11);
		}

		// access custom field
		Map<String, Field> fieldMap = getFieldMap(po.getType());
		Field field = fieldMap.get(name);
		if (field == null) {
			if (po instanceof Sysprop) {
				Sysprop so = (Sysprop) po;
				return so.getProperty(name);
			}
			return null;
		}

		try {
			// access standard field
			return PropertyUtils.getProperty(po, name);
		} catch (Exception e) {
			try {
				return PropertyUtils.getProperty(po, field.getName());
			} catch (Exception e1) {
				return null;
			}
		}
	}

	public static Object getProperty(ParaObject po, String name, Object defaultValue) {
		Object value = getProperty(po, name);
		return value == null ? defaultValue : value;
	}

	public static String getPropertyAsString(ParaObject po, String name) {
		Object value = getProperty(po, name);
		if (value == null) return "";
		if (value instanceof String) return (String) value;
		return value.toString();
	}

	public static long getPropertyAsLong(ParaObject po, String name) {
		Object value = getProperty(po, name);
		if (value == null) return 0;
		if (value instanceof Boolean) return ((Boolean) value) ? 1 : 0;
		if (value instanceof Integer) return (Integer) value;
		if (value instanceof Long) return (Long) value;
		if (value instanceof Date) return ((Date) value).getTime();

		String str = (value instanceof String) ? (String) value : value.toString();
		if (str.length() >= 2 && str.charAt(0) == '"' && str.charAt(str.length() - 1) == '"') {
			str = str.substring(1, str.length() - 1);
		}

		return Long.parseLong(str);
	}
	public static Timestamp toTimestamp(Object value) {
		if (value instanceof Timestamp) {
			return (Timestamp) value;
		}

		if (value instanceof Date) {
			return new Timestamp(((Date) value).getTime());
		}

		if (value == null) {
			return epoch;
		}

		String str = value.toString().trim();
		while (str.length() > 1) {
			if (str.charAt(0) == '"' && str.charAt(str.length() - 1) == '"') {
				str = str.substring(1, str.length()).trim();
			} else if (str.charAt(0) == '\'' && str.charAt(str.length() - 1) == '\'') {
				str = str.substring(1, str.length()).trim();
			} else {
				break;
			}
		}

		String[] fmtList = searchDateFormat.split("\\|\\|");
		for (String fmt : fmtList) {
			try {
				if ("epoch_millis".equalsIgnoreCase(fmt.trim())) {
					return new Timestamp(Long.parseLong(str));
				} else if ("epoch_second".equalsIgnoreCase(fmt.trim())) {
					return new Timestamp(Long.parseLong(str) * 1000L);
				} else if (str.length() == fmt.length()){
					SimpleDateFormat parser = new SimpleDateFormat(fmt.trim());
					return new Timestamp(parser.parse(str).getTime());
				}
			} catch (Exception ignored) {}
		}

		return epoch;
	}

	public static Date getPropertyAsDate(ParaObject po, String name) {
		Object value = getProperty(po, name);
		if (value == null) return null;
		return toTimestamp(value);
	}

	public static Date getPropertyAsDate(ParaObject po, String name, Date defaultValue) {
		Date date = getPropertyAsDate(po, name);
		return date == null ? defaultValue : date;
	}

	public static ParaObject setProperty(ParaObject po, String name, Object value) {
		if (po == null || name == null || name.isEmpty()) {
			return po;
		}

		if (name.startsWith("properties.")) {
			name = name.substring(11);
		}

		// access custom field
		Map<String, Field> fieldMap = getFieldMap(po.getType());
		Field field = fieldMap.get(name);
		if (field == null) {
			if (po instanceof Sysprop) {
				Sysprop so = (Sysprop) po;
				so.getProperties().put(name, value);
				return po;
			}
			return po;
		}

		try {
			// access standard field
			PropertyUtils.setProperty(po, name, value);
		} catch (Exception ignored) {
			logger.error("setProperty failed, po:{}, name: {}, value: {}", po, name, value, ignored);
		}

		return po;
	}
}
