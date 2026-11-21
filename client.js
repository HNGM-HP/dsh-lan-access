window.__ModuleLoader__.load({
  id: '@local/dsh-lan-access',
  factory(require) {
    const React = require('react');
    const h = React.createElement;
    const { useCallback, useEffect, useState } = React;

    const styles = {
      root: { display: 'flex', flexDirection: 'column', gap: 18, padding: '4px 2px', fontSize: 13 },
      intro: { color: 'var(--dsw-alias-label-secondary, #666)', lineHeight: 1.6, margin: 0 },
      row: { display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, padding: '10px 12px', border: '1px solid var(--dsw-alias-border-l2, #ddd)', borderRadius: 10 },
      main: { display: 'flex', flexDirection: 'column', gap: 2, minWidth: 0 },
      title: { fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' },
      sub: { color: 'var(--dsw-alias-label-tertiary, #888)', fontSize: 12, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' },
      sectionTitle: { fontSize: 14, fontWeight: 600, margin: '4px 0 0' },
      empty: { color: 'var(--dsw-alias-label-tertiary, #888)', fontSize: 12, padding: '6px 2px' },
      actions: { display: 'flex', gap: 8, flexShrink: 0 },
      button: { border: '1px solid var(--dsw-alias-border-l2, #ccc)', borderRadius: 7, background: 'var(--dsw-alias-bg-l2, #f5f5f5)', color: 'var(--dsw-alias-label-primary, #222)', padding: '5px 10px', fontSize: 12, cursor: 'pointer' },
      primary: { border: '1px solid #247bbf', background: '#247bbf', color: '#fff' },
      error: { color: '#c0392b', fontSize: 12, margin: 0 },
      status: { display: 'flex', gap: 12, color: 'var(--dsw-alias-label-secondary, #666)', fontSize: 12 },
    };

    async function request(path, options = {}) {
      const { headers, ...rest } = options;
      const response = await fetch(path, {
        cache: 'no-store',
        credentials: 'same-origin',
        ...rest,
        headers: { 'x-dsh-lan-admin': '1', ...(headers ?? {}) },
      });
      let value = null;
      try { value = await response.json(); } catch { value = null; }
      if (!response.ok) {
        const error = new Error(value?.message ?? value?.error ?? `HTTP ${response.status}`);
        error.status = response.status;
        throw error;
      }
      return value;
    }

    function formatTime(value) {
      if (typeof value !== 'number') return '';
      try { return new Date(value).toLocaleString(); } catch { return ''; }
    }

    function Section() {
      const [state, setState] = useState(null);
      const [error, setError] = useState('');
      const [busy, setBusy] = useState('');

      const refresh = useCallback(async () => {
        try {
          const value = await request('/lan-access/api/state');
          setState(value);
          setError('');
        } catch (failure) {
          if (location.protocol !== 'http:' && location.protocol !== 'https:') {
            setError('Desktop 请打开 http://127.0.0.1:8097/__manage 管理设备（本机回环管理页）。');
          } else {
            setError(failure.status === 401
              ? '请通过 owner 的 DSH Web 登录后再管理设备。'
              : String(failure.message ?? failure));
          }
        }
      }, []);

      useEffect(() => {
        void refresh();
        const timer = setInterval(() => { void refresh(); }, 2500);
        return () => clearInterval(timer);
      }, [refresh]);

      const act = useCallback(async (id, action) => {
        setBusy(id + action);
        try {
          const value = await request(`/lan-access/api/${action}`, {
            method: 'POST',
            headers: { 'content-type': 'application/json' },
            body: JSON.stringify({ id })
          });
          setState((previous) => previous === null ? previous : { ...previous, pending: value.pending, devices: value.devices });
          setError('');
        } catch (failure) {
          setError(String(failure.message ?? failure));
        } finally {
          setBusy('');
        }
      }, []);

      const pending = state?.pending ?? [];
      const devices = state?.devices ?? [];

      return h('div', { style: styles.root },
        h('p', { style: styles.intro },
          '手机、平板或其它浏览器第一次访问局域网入口时会停在这里等待。允许后，该设备会获得一个持久设备凭据，之后打开的就是原生 DSH Web 界面。移除设备会立即撤销它的访问。'),
        state === null
          ? (error ? h('p', { style: styles.error }, error) : h('p', { style: styles.empty }, '正在读取设备状态…'))
          : h('div', { style: styles.status },
              h('span', null, `监听：${state.bind}:${state.port}`),
              h('span', null, `上游：${state.upstream}`),
              h('span', null, `待批准：${pending.length}`),
              h('span', null, `已批准：${devices.length}`)),
        error ? h('p', { style: styles.error }, error) : null,
        h('h3', { style: styles.sectionTitle }, '待批准设备'),
        pending.length === 0
          ? h('p', { style: styles.empty }, '没有待批准的设备。')
          : pending.map((item) => h('div', { key: item.id, style: styles.row },
              h('div', { style: styles.main },
                h('span', { style: styles.title }, item.label),
                h('span', { style: styles.sub }, `${formatTime(item.createdAt)} · ${item.address || '未知地址'}${item.fingerprint ? ' · 指纹 ' + item.fingerprint.slice(0, 12) : ''}`)),
              h('div', { style: styles.actions },
                h('button', { type: 'button', style: { ...styles.button, ...styles.primary }, disabled: busy !== '', onClick: () => void act(item.id, 'approve') }, '允许'),
                h('button', { type: 'button', style: styles.button, disabled: busy !== '', onClick: () => void act(item.id, 'reject') }, '拒绝')))),
        h('h3', { style: styles.sectionTitle }, '已批准设备'),
        devices.length === 0
          ? h('p', { style: styles.empty }, '还没有已批准的设备。')
          : devices.map((item) => h('div', { key: item.id, style: styles.row },
              h('div', { style: styles.main },
                h('span', { style: styles.title }, item.label),
                h('span', { style: styles.sub }, `批准于 ${formatTime(item.approvedAt)} · 最后活跃 ${formatTime(item.lastSeen)}${item.fingerprint ? ' · 指纹 ' + item.fingerprint.slice(0, 12) : ''}`)),
              h('div', { style: styles.actions },
                h('button', { type: 'button', style: styles.button, disabled: busy !== '', onClick: () => void act(item.id, 'remove') }, '移除')))));
    }

    return {
      inject: ['slots'],
      apply(ctx) {
        ctx.slots.inject('settings.section', () => ctx.slots.register({
          name: 'settings.section',
          id: 'lan-access',
          order: 100,
          label: () => '局域网访问',
        }, Section));
      },
    };
  },
});
