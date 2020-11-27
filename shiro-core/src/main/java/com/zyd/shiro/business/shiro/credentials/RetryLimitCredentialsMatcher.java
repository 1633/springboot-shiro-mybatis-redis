/**
 * MIT License
 * Copyright (c) 2018 yadong.zhang
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package com.zyd.shiro.business.shiro.credentials;

import com.zyd.shiro.business.consts.SessionConst;
import com.zyd.shiro.business.entity.User;
import com.zyd.shiro.business.service.SysUserService;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AccountException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.ExcessiveAttemptsException;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.concurrent.TimeUnit;

/**
 * Shiro-密码输入错误的状态下重试次数的匹配管理
 *
 * @author yadong.zhang (yadong.zhang0415(a)gmail.com)
 * @version 1.0
 * @website https://www.zhyd.me
 * @date 2018/4/24 14:37
 * @since 1.0
 */
@Slf4j
public class RetryLimitCredentialsMatcher extends CredentialsMatcher {

    /**
     * 用户登录次数计数  redisKey 前缀
     */
    private static final String SHIRO_LOGIN_COUNT = "shiro_login_count_";
    /**
     * 用户登录是否被锁定    一小时 redisKey 前缀
     */
    private static final String SHIRO_IS_LOCK = "shiro_is_lock_";
    @Autowired
    private SysUserService userService;

    @Override
    public boolean doCredentialsMatch(AuthenticationToken token, AuthenticationInfo info) {
        Long userId = (Long) info.getPrincipals().getPrimaryPrincipal();
        User user = userService.getByPrimaryKey(userId);
        String username = user.getUsername();
        // 访问一次，计数一次
        String loginCountKey = SHIRO_LOGIN_COUNT + username;
        String isLockKey = SHIRO_IS_LOCK + username;



        boolean matches = super.doCredentialsMatch(token, info);
        if (!matches) {
//            String msg = retryCount <= 0 ? "您的账号一小时内禁止登录！" : "您还剩" + retryCount + "次重试的机会";
//            throw new AccountException("帐号或密码不正确！" + msg);
        }

        try {
            userService.updateUserLastLoginInfo(user);
        } catch (Exception e) {
            e.printStackTrace();
        }
        // 当验证都通过后，把用户信息放在session里
        // 注：User必须实现序列化
        SecurityUtils.getSubject().getSession().setAttribute(SessionConst.USER_SESSION_KEY, user);
        return true;
    }
}
