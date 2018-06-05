package com.imooc.shiro.realm;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

public class CustomRealm extends AuthorizingRealm {

	Map<String, String> userMap = new HashMap<String, String>();
	{
		userMap.put("Harry", "49da865e1ceae5f5484973239ace04f8");
		super.setName("customRealm");
	}
	
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		String username = (String) principals.getPrimaryPrincipal();
		Set<String> roles = getRolesByUsername(username);
		Set<String> permissions = getPermissionByUsername("username");
		
		SimpleAuthorizationInfo authorizationInfo = new SimpleAuthorizationInfo();
		authorizationInfo.addRoles(roles);
		authorizationInfo.addStringPermissions(permissions);
		return authorizationInfo;
	}

	private Set<String> getPermissionByUsername(String username) {
		Set<String> set = new HashSet<String>();
		set.add("user:delete");
		set.add("user:update");
		return set;
	}

	private Set<String> getRolesByUsername(String username) {
		Set<String> set = new HashSet<String>();
		set.add("admin");
		set.add("user");
		return set;
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		String username = (String) token.getPrincipal();
		String password = getPasswordByUsername(username);
		if (password == null) {
			return null;
		}
		SimpleAuthenticationInfo authenticationInfo = new SimpleAuthenticationInfo(username,password,this.getName());
		//加盐
		authenticationInfo.setCredentialsSalt(ByteSource.Util.bytes(username));
		return authenticationInfo;
	}

	private String getPasswordByUsername(String username) {
		
		return userMap.get(username);
	}

	
}
