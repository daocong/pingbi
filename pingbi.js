/**
 * @author Coco
 * @QQ:594277625
 * @name httphijack 1.0.0
 * @update : 2016-08-10
 * @description 使用Javascript实现前端防御http劫持及防御XSS攻击，并且对可疑攻击进行上报
 * -=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 *

 *
 */


  // 建立白名单
  var whiteList = [
    'www.pp1500',
    'daocong',
  ];


  // 建立关键词黑名单
  var keywordBlackList = [
    'script',
  ];


 
  /**
   * 重写单个 window 窗口的 document.write 属性
   * @param  {[BOM]} window [浏览器window对象]
   * @return {[type]}       [description]
   */
    var old_write = window.document.writeln;

    window.document.writeln = function(string) {
      if (blackListMatch(keywordBlackList, string)) {
        console.log('拦截可疑模块:', string);
        return;
      }

      // 调用原始接口
      old_write.apply(document, arguments);
    }



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



