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
package com.erudika.para.aop;

import com.erudika.para.IOListener;
import com.erudika.para.Para;
import com.erudika.para.annotations.Cached;
import com.erudika.para.annotations.Indexed;
import com.erudika.para.cache.Cache;
import com.erudika.para.core.ParaObject;
import com.erudika.para.persistence.DAO;
import com.erudika.para.search.Search;
import com.erudika.para.utils.Config;
import com.erudika.para.validation.ValidationUtils;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import javax.inject.Inject;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * This is the core method interceptor which enables caching and indexing.
 * It listens for calls to annotated {@link com.erudika.para.persistence.DAO} methods
 * and adds searching and caching functionality to them. This technique allows us to control
 * the caching and searching centrally for all implementations
 * of the {@link com.erudika.para.persistence.DAO} interface.
 * @author Alex Bogdanovski [alex@erudika.com]
 * @see com.erudika.para.persistence.DAO
 */
@SuppressWarnings("unchecked")
public class IndexAndCacheAspect implements MethodInterceptor {

	private static final Logger logger = LoggerFactory.getLogger(IndexAndCacheAspect.class);

	private Search search;
	private Cache cache;

	/**
	 * @return {@link Search}
	 */
	public Search getSearch() {
		return search;
	}

	/**
	 * @param search {@link Search}
	 */
	@Inject
	public void setSearch(Search search) {
		this.search = search;
	}

	/**
	 * @return {@link Cache}
	 */
	public Cache getCache() {
		return cache;
	}

	/**
	 * @param cache {@link Cache}
	 */
	@Inject
	public void setCache(Cache cache) {
		this.cache = cache;
	}

	/**
	 * Executes code when a method is invoked. A big switch statement.
	 * @param mi method invocation
	 * @return the returned value of the method invoked or something else (decided here)
	 * @throws Throwable error
	 */
	public Object invoke(MethodInvocation mi) throws Throwable {
		if (!Modifier.isPublic(mi.getMethod().getModifiers())) {
			return mi.proceed();
		}
		Method m = mi.getMethod();
		Method superMethod = null;
		Indexed indexedAnno = null;
		Cached cachedAnno = null;

		try {
			superMethod = DAO.class.getMethod(m.getName(), m.getParameterTypes());
			indexedAnno = Config.isSearchEnabled() ? superMethod.getAnnotation(Indexed.class) : null;
			cachedAnno = Config.isCacheEnabled() ? superMethod.getAnnotation(Cached.class) : null;
		} catch (Exception e) {
			if (! (e instanceof NoSuchMethodException)) {
				logger.error(null, e);
			} else {
				logger.error("DAO class no method '{}'", m.getName());
			}
		}

		Object[] args = mi.getArguments();
		String appid = AOPUtils.getFirstArgOfString(args);
		List<IOListener> ioListeners = Para.getIOListeners();

		for (IOListener ioListener : ioListeners) {
			ioListener.onPreInvoke(superMethod, args);
			logger.debug("Executed {}.onPreInvoke().", ioListener.getClass().getName());
		}

		Object result = handleIndexing(indexedAnno, appid, args, mi);
		Object cachingResult = handleCaching(cachedAnno, appid, args, mi);

		// we have a read operation without any result but we get back objects from cache
		if (result == null && cachingResult != null) {
			result = cachingResult;
		}

		// both searching and caching are disabled - pass it through
		if (indexedAnno == null && cachedAnno == null) {
			result = mi.proceed();
		}

		for (IOListener ioListener : ioListeners) {
			ioListener.onPostInvoke(superMethod, result);
			logger.debug("Executed {}.onPostInvoke().", ioListener.getClass().getName());
		}

		return result;
	}

	private Object handleIndexing(Indexed indexedAnno, String appid, Object[] args, MethodInvocation mi)
			throws Throwable {
		Object result = null;
		if (indexedAnno != null) {
			switch (indexedAnno.action()) {
				case ADD:
					result = addToIndexOperation(appid, args, mi);
					break;
				case REMOVE:
					result = removeFromIndexOperation(appid, args, mi);
					break;
				case ADD_ALL:
					result = addToIndexBatchOperation(appid, args, mi);
					break;
				case REMOVE_ALL:
					result = removeFromIndexBatchOperation(appid, args, mi);
					break;
				default:
					break;
			}
		}
		return result;
	}

	private Object handleCaching(Cached cachedAnno, String appid, Object[] args, MethodInvocation mi)
			throws Throwable {
		Object result = null;
		if (cachedAnno != null) {
			switch (cachedAnno.action()) {
				case GET:
					result = readFromCacheOperation(appid, args, mi);
					break;
				case PUT:
					addToCacheOperation(appid, args);
					break;
				case DELETE:
					removeFromCacheOperation(appid, args);
					break;
				case GET_ALL:
					result = readFromCacheBatchOperation(appid, args, mi);
					break;
				case PUT_ALL:
					addToCacheBatchOperation(appid, args);
					break;
				case DELETE_ALL:
					removeFromCacheBatchOperation(appid, args);
					break;
				default:
					break;
			}
		}
		return result;
	}

	private Object addToIndexOperation(String appid, Object[] args, MethodInvocation mi) throws Throwable {
		ParaObject addMe = AOPUtils.getArgOfParaObject(args);
		String[] errors = ValidationUtils.validateObject(addMe);
		Object result = null;
		if (addMe != null && errors.length == 0) {
			AOPUtils.checkAndFixType(addMe);
			if (addMe.getStored()) {
				result = mi.proceed();
			}
			if (addMe.getIndexed()) {
				search.index(appid, addMe);
				logger.debug("{}: Indexed {}->{}", getClass().getSimpleName(), appid, addMe.getId());
			}
		} else {
			logger.warn("{}: Invalid object {}->{} errors: [{}]. Changes weren't persisted.",
					getClass().getSimpleName(), appid, addMe, String.join("; ", errors));
		}
		return result;
	}

	private Object removeFromIndexOperation(String appid, Object[] args, MethodInvocation mi) throws Throwable {
		Object result = mi.proceed(); // delete from DB even if "isStored = false"
		ParaObject removeMe = AOPUtils.getArgOfParaObject(args);
		AOPUtils.checkAndFixType(removeMe);
		search.unindex(appid, removeMe); // remove from index even if "isIndexed = false"
		logger.debug("{}: Unindexed {}->{}", getClass().getSimpleName(), appid,
				(removeMe == null) ? null : removeMe.getId());
		return result;
	}

	private Object addToIndexBatchOperation(String appid, Object[] args, MethodInvocation mi)
			throws Throwable {
		List<ParaObject> addUs = AOPUtils.getArgOfListOfType(args, ParaObject.class);
		List<ParaObject> indexUs = new LinkedList<>();
		List<ParaObject> removedObjects = AOPUtils.removeNotStoredNotIndexed(addUs, indexUs);
		Object result = mi.proceed();
		search.indexAll(appid, indexUs);
		// restore removed objects - needed if we have to cache them later
		// do not remove this line - breaks tests
		if (addUs != null) {
			addUs.addAll(removedObjects); // don't delete!
		}
		logger.debug("{}: Indexed all {}->{}", getClass().getSimpleName(), appid, indexUs.size());
		return result;
	}

	private Object removeFromIndexBatchOperation(String appid, Object[] args, MethodInvocation mi) throws Throwable {
		List<ParaObject> removeUs = AOPUtils.getArgOfListOfType(args, ParaObject.class);
		Object result = mi.proceed(); // delete from DB even if "isStored = false"
		search.unindexAll(appid, removeUs); // remove from index even if "isIndexed = false"
		logger.debug("{}: Unindexed all {}->{}", getClass().getSimpleName(),
				appid, (removeUs == null) ? null : removeUs.size());
		return result;
	}

	private Object readFromCacheOperation(String appid, Object[] args, MethodInvocation mi) throws Throwable {
		Object result = null;
		String getMeId = (args != null && args.length > 1) ? (String) args[1] : null;
		if (cache.contains(appid, getMeId)) {
			result = cache.get(appid, getMeId);
			logger.debug("{}: Cache hit: {}->{}", getClass().getSimpleName(), appid, getMeId);
		} else if (getMeId != null) {
			result = mi.proceed();
			if (result != null && ((ParaObject) result).getCached()) {
				cache.put(appid, getMeId, result);
				logger.debug("{}: Cache miss: {}->{}", getClass().getSimpleName(), appid, getMeId);
			}
		}
		return result;
	}

	private void addToCacheOperation(String appid, Object[] args) {
		ParaObject putMe = AOPUtils.getArgOfParaObject(args);
		if (putMe != null && putMe.getCached()) {
			cache.put(appid, putMe.getId(), putMe);
			logger.debug("{}: Cache put: {}->{}", getClass().getSimpleName(), appid, putMe.getId());
		}
	}

	private void removeFromCacheOperation(String appid, Object[] args) {
		ParaObject deleteMe = AOPUtils.getArgOfParaObject(args);
		if (deleteMe != null) { // clear from cache even if "isCached = false"
			cache.remove(appid, deleteMe.getId());
			logger.debug("{}: Cache delete: {}->{}", getClass().getSimpleName(), appid, deleteMe.getId());
		}
	}

	private Object readFromCacheBatchOperation(String appid, Object[] args, MethodInvocation mi) throws Throwable {
		Object result = Collections.emptyMap();
		List<String> getUs = AOPUtils.getArgOfListOfType(args, String.class);
		if (getUs != null) {
			Map<String, ParaObject> cached = cache.getAll(appid, getUs);
			logger.debug("{}: Cache getAll(): {}->{}", getClass().getSimpleName(), appid, getUs);
			// hit the database if even a single object is missing from cache, then cache it
			if (cached.size() < getUs.size()) {
				logger.debug("{}: Cache getAll() will read from DB: {}", getClass().getSimpleName(), appid);
				result = mi.proceed();
				if (result != null) {
					for (String id : getUs) {
						logger.debug("{}: Cache getAll() got from DB: {}", getClass().getSimpleName(), id);
						if (!cached.containsKey(id)) {
							ParaObject obj = ((Map<String, ParaObject>) result).get(id);
							if (obj != null && obj.getCached()) {
								cache.put(appid, obj.getId(), obj);
								logger.debug("{}: Cache miss on readAll: {}->{}", getClass().getSimpleName(), appid, id);
							}
						}
					}
				}
			}
			if (result == null || ((Map) result).isEmpty()) {
				result = cached;
			}
		}
		return result;
	}

	private void addToCacheBatchOperation(String appid, Object[] args) {
		List<ParaObject> putUs = AOPUtils.getArgOfListOfType(args, ParaObject.class);
		if (putUs != null && !putUs.isEmpty()) {
			Map<String, ParaObject> map1 = new LinkedHashMap<>(putUs.size());
			for (ParaObject obj : putUs) {
				if (obj != null && obj.getCached()) {
					map1.put(obj.getId(), obj);
				}
			}
			if (!map1.isEmpty()) {
				cache.putAll(appid, map1);
			}
			logger.debug("{}: Cache put page: {}->{}", getClass().getSimpleName(), appid, map1.keySet());
		}
	}

	private void removeFromCacheBatchOperation(String appid, Object[] args) {
		List<ParaObject> deleteUs = AOPUtils.getArgOfListOfType(args, ParaObject.class);
		if (deleteUs != null && !deleteUs.isEmpty()) {
			List<String> list = new ArrayList<>(deleteUs.size());
			for (ParaObject paraObject : deleteUs) {
				list.add(paraObject.getId());
			}
			// clear from cache even if "isCached = false"
			cache.removeAll(appid, list);
			logger.debug("{}: Cache delete page: {}->{}", getClass().getSimpleName(), appid, list);
		}
	}

}
