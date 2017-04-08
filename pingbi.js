/**
 * @author Coco
 * @QQ:308695699
 * @name httphijack 1.0.0
 * @update : 2016-08-10
 * @description 使用Javascript实现前端防御http劫持及防御XSS攻击，并且对可疑攻击进行上报
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *
1、使用方法：调用 httphijack.init()
2、建立自己的黑白名单、上报系统及接收后端
3、防范范围：
   1）所有内联事件执行的代码
   2）href 属性 javascript: 内嵌的代码
   3）静态脚本文件内容
   4）动态添加的脚本文件内容
   5）document-write添加的内容
   6）iframe嵌套
 *
 */


  // 建立白名单
  var whiteList = [
    'www.aaa.com',
    'www.bbb.com',
    's4.cnzz.com'
  ];

  // 建立黑名单
  var blackList = [
    '192.168.1.0'
  ];

  // 建立关键词黑名单
  var keywordBlackList = [
    'xss',
    'BAIDU_SSP__wrapper',
    'BAIDU_DSPUI_FLOWBAR'
  ];




  // 主动防御 MutationEvent
  /**
   * 使用 MutationObserver 进行静态脚本拦截
   * @return {[type]} [description]
   */

    // MutationObserver 的不同兼容性写法
    var MutationObserver = window.MutationObserver || window.WebKitMutationObserver || window.MozMutationObserver;

    // 该构造函数用来实例化一个新的 Mutation 观察者对象
    // Mutation 观察者对象能监听在某个范围内的 DOM 树变化
    var observer = new MutationObserver(function(mutations) {
      mutations.forEach(function(mutation) {
        // 返回被添加的节点,或者为null.
        var nodes = mutation.addedNodes;

        // 逐个遍历
        for (var i = 0; i < nodes.length; i++) {
          var node = nodes[i];

          // 扫描 script 与 iframe
          if (node.tagName === 'SCRIPT' || node.tagName === 'IFRAME') {
            // 拦截到可疑iframe
            if (node.tagName === 'IFRAME' && node.srcdoc) {
              node.parentNode.removeChild(node);
              console.log('拦截到可疑iframe', node.srcdoc);
              hijackReport('拦截可疑静态脚本', node.srcdoc);

            } else if (node.src) {
              // 只放行白名单
              if (!whileListMatch(whiteList, node.src)) {
                node.parentNode.removeChild(node);
                // 上报
                console.log('拦截可疑静态脚本:', node.src);
                hijackReport('拦截可疑静态脚本', node.src);
              }
            }
          }
        }
      });
    });

    // 传入目标节点和观察选项
    // 如果 target 为 document 或者 document.documentElement
    // 则当前文档中所有的节点添加与删除操作都会被观察到d
    observer.observe(document, {
      subtree: true,
      childList: true
    });



  // 重写 createElement
  function resetCreateElement() {}

  /**
   * 重写单个 window 窗口的 document.write 属性
   * @param  {[BOM]} window [浏览器window对象]
   * @return {[type]}       [description]
   */
    var old_write = window.document.writeln;

    window.document.writeln = function(string) {
      if (blackListMatch(keywordBlackList, string)) {
        console.log('拦截可疑模块:', string);
        hijackReport('拦截可疑document-write', string);
        return;
      }

      // 调用原始接口
      old_write.apply(document, arguments);
    }

  
  /**
   * [白名单匹配]
   * @param  {[Array]} whileList [白名单]
   * @param  {[String]} value    [需要验证的字符串]
   * @return {[Boolean]}         [false -- 验证不通过，true -- 验证通过]
   */
  function whileListMatch(whileList, value) {
    var length = whileList.length,
      i = 0;

    for (; i < length; i++) {
      // 建立白名单正则
      var reg = new RegExp(whiteList[i], 'i');

      // 存在白名单中，放行
      if (reg.test(value)) {
        return true;
      }
    }
    return false;
  }

  /**
   * [黑名单匹配]
   * @param  {[Array]} blackList [黑名单]
   * @param  {[String]} value    [需要验证的字符串]
   * @return {[Boolean]}         [false -- 验证不通过，true -- 验证通过]
   */
  function blackListMatch(blackList, value) {
    var length = blackList.length,
      i = 0;

    for (; i < length; i++) {
      // 建立黑名单正则
      var reg = new RegExp(blackList[i], 'i');

      // 存在黑名单中，拦截
      if (reg.test(value)) {
        return true;
      }
    }
    return false;
  }



